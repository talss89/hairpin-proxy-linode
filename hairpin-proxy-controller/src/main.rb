#!/usr/bin/env ruby
# frozen_string_literal: true

require "k8s-ruby"
require "logger"
require "optparse"
require "socket"
require "digest"

VERSION = "0.3.1"

class HairpinProxyController
  COMMENT_LINE_SUFFIX = "# Added by hairpin-proxy"
  POLL_INTERVAL = ENV.fetch("POLL_INTERVAL", "15").to_i.clamp(1..)

  # Kubernetes <= 1.18 puts Ingress in "extensions/v1beta1"
  # Kubernetes >= 1.19 puts Ingress in "networking.k8s.io/v1"
  # (We search both for maximum compatibility.)
  INGRESS_API_VERSIONS = ["networking.k8s.io/v1"].freeze

  def initialize
    @dry_run = false
    @k8s = K8s::Client.autoconfig
    @ingresses= Hash.new
    @namespace= ENV.fetch('POD_NAMESPACE','hairpin-proxy')

    @image='sumcumo/hairpin-proxy-haproxy' #'sumcumo/hairpin-proxy-haproxy'
    @version=VERSION
    @addr_to_proxy_svc = Hash.new { |hash,key| hash[key] = proxy_service_name(key) }

    STDOUT.sync = true
    @log = Logger.new(STDOUT)
  end

  def fetch_ingress_hosts
    result = Hash.new

    @k8s.apis(INGRESS_API_VERSIONS, skip_missing: true).each do |client|
      client.resource("ingresses").list.each do |ing| 
        next unless ing.status.loadBalancer.ingress
        next ing.spec.tls unless ing.spec.tls
        ing.status.loadBalancer.ingress.each do |lb| 
          addr = @addr_to_proxy_svc[lb.ip || lb.hostname]
          ing.spec.tls.map(&:hosts).flatten.sort.uniq.each do |host|
            next unless /\A[A-Za-z0-9.\-_]+\z/.match?(host)
            result[host] =addr
          end
        end
      end
    end

    return result
  end

  def coredns_corefile_with_rewrite_rules(original_corefile, hosts)
    # Return a String representing the original CoreDNS Corefile, modified to include rewrite rules for each of *hosts.
    # This is an idempotent transformation because our rewrites are labeled with COMMENT_LINE_SUFFIX.

    # Extract base configuration, without our hairpin-proxy rewrites
    cflines = original_corefile.strip.split("\n").reject { |line| line.strip.end_with?(COMMENT_LINE_SUFFIX) }

    # Create rewrite rules
    rewrite_lines = hosts.map { |host,destination| "    rewrite name #{host} #{destination} #{COMMENT_LINE_SUFFIX}" }

    # Inject at the start of the main ".:53 { ... }" configuration block
    main_server_line = cflines.index { |line| line.strip.start_with?(".:53 {") }
    raise "Can't find main server line! '.:53 {' in Corefile" if main_server_line.nil?
    cflines.insert(main_server_line + 1, *rewrite_lines)

    cflines.join("\n")
  end

  def check_and_rewrite_coredns
    @log.info("Polling all Ingress resources and CoreDNS configuration...")
    hosts = fetch_ingress_hosts
    cm = @k8s.api.resource("configmaps", namespace: "kube-system").get("coredns")

    old_corefile = cm.data.Corefile
    new_corefile = coredns_corefile_with_rewrite_rules(old_corefile, hosts)

    if old_corefile.strip != new_corefile.strip
      @log.info("Corefile has changed! New contents:\n#{new_corefile}#{"\nSending updated ConfigMap to Kubernetes API server..." unless @dry_run}")
      cm.data.Corefile = new_corefile
      @k8s.api.resource("configmaps", namespace: "kube-system").update_resource(cm) unless @dry_run
    end
  end

  def dns_rewrite_destination_ip_address
    Addrinfo.ip(DNS_REWRITE_DESTINATION).ip_address
  end

  def etchosts_with_rewrite_rules(original_etchosts, hosts)
    # Returns a String represeting the original /etc/hosts file, modified to include a rule for
    # mapping *hosts to dns_rewrite_destination_ip_address. This handles kubelet and the node's Docker engine,
    # which does not go through CoreDNS.
    # This is an idempotent transformation because our rewrites are labeled with COMMENT_LINE_SUFFIX.

    # Extract base configuration, without our hairpin-proxy rewrites
    our_lines, original_lines = original_etchosts.strip.split("\n").partition { |line| line.strip.end_with?(COMMENT_LINE_SUFFIX) }

    ip = dns_rewrite_destination_ip_address
    hostlist = hosts.join(" ")
    new_rewrite_line = "#{ip}\t#{hostlist} #{COMMENT_LINE_SUFFIX}"

    if our_lines == [new_rewrite_line]
      # Return early so that we're indifferent to the ordering of /etc/hosts lines.
      return original_etchosts
    end

    (original_lines + [new_rewrite_line]).join("\n") + "\n"
  end

  def check_and_rewrite_etchosts(etchosts_path)
    @log.info("Polling all Ingress resources and etchosts file at #{etchosts_path}...")
    hosts = fetch_ingress_hosts

    old_etchostsfile = File.read(etchosts_path)
    new_etchostsfile = etchosts_with_rewrite_rules(old_etchostsfile, hosts)

    if old_etchostsfile.strip != new_etchostsfile.strip
      @log.info("#{"[dry-run] " if @dry_run}/etc/hosts has changed! New contents:\n#{new_etchostsfile}\nWriting to #{etchosts_path}...")
      File.write(etchosts_path, new_etchostsfile) unless @dry_run
    end
  end

  def create_proxy(address, ingress_service_name)
    enc_address = address_digest(address)
    deployment = K8s::Resource.new({
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      metadata:{
        namespace: @namespace,
        name: "haproxy-#{enc_address}",
        labels: {
          'app.kubernetes.io/name' => "hairpin-proxy",
          'app.kubernetes.io/instance' => "haproxy-#{enc_address}",
          'app.kubernetes.io/version' => @version,
          'app.kubernetes.io/component' => "haproxy",
          'app.kubernetes.io/part-of' => "hairpin-proxy",
          'app.kubernetes.io/managed-by' => "hairpin-proxy-controller",
          'proxy-target' => ingress_service_name,
        },
      },
      spec:{
        replicas: 1,
        selector: {
            matchLabels: {
              'app.kubernetes.io/instance' => "haproxy-#{enc_address}",
            }
        },
        template: {
          metadata: {
              labels: {
                'app.kubernetes.io/instance' => "haproxy-#{enc_address}",
              },
          },
          spec: {
              containers: [{
                  image: "#{@image}:#{@version}",
                  name: "haproxy",
                  resources: {
                      requests: {
                          memory: "100Mi",
                          cpu: "100m",
                      },
                      limits: {
                          memory: "200Mi",
                          cpu: "150m",
                      }
                  },
                  env: [{
                      name: "TARGET_SERVER",
                      value: ingress_service_name
                  }],
              }]
          },
        }
      }
    })
       
    unless @dry_run
      @log.info "Create deployment=#{deployment.metadata.name} in namespace=#{deployment.metadata.namespace}"
      deployment = @k8s.update_resource(deployment)
    else
      @log.info "[dry-run] Create deployment=#{deployment.metadata.name} in namespace=#{deployment.metadata.namespace}: \n #{deployment.to_yaml}"
    end 

    service = K8s::Resource.new({
      apiVersion: 'v1',
      kind: 'Service',
      metadata: {
        namespace: @namespace,
        name: @addr_to_proxy_svc[address],
        labels: {
          'app.kubernetes.io/name' => "hairpin-proxy",
          'app.kubernetes.io/instance' => "haproxy-#{enc_address}",
          'app.kubernetes.io/version' =>  @version,
          'app.kubernetes.io/component' => "haproxy-service",
          'app.kubernetes.io/part-of' => "hairpin-proxy",
          'app.kubernetes.io/managed-by' => "hairpin-proxy-controller",
          'proxy-target' => ingress_service_name,
        },
      },
      spec: {
        type: 'ClusterIP',
        ports: [
          { 
            name: "http",
            port: 80 
          },
          { 
            name: "https",
            port: 443
          },
        ],
        selector: { 'app.kubernetes.io/instance' => "haproxy-#{enc_address}"},
      },  
    })

    unless @dry_run
      @log.info "Create service=#{service.metadata.name} in namespace=#{service.metadata.namespace}"
      service = @k8s.update_resource(service)
    else
      @log.info "[dry-run] Create service=#{service.metadata.name} in namespace=#{service.metadata.namespace}\n#{service.to_yaml}"
    end

    return {
      deployment: deployment,
      service: service,
    }
  end

  def remove_proxy(ip_address)
    proxy = @ingresses.delete[ip_address]
    return unless proxy && !@dry_run
    @k8s.delete_resource(proxy.service)
    @k8s.delete_resource(proxy.deployment)
  end

  def address_digest(address)
    Digest::SHA256.hexdigest(address).slice(0..12)
  end

  def proxy_service_name(address)
    "proxy-#{address_digest(address)}.#{@namespace}.svc.cluster.local"
  end

  def find_ingresses
    known = @ingresses.keys

    @k8s.api('v1').resource("services").list().each do |svc| 
      if svc.spec.type == 'LoadBalancer'
        svc_name = "#{svc.metadata.name}.#{svc.metadata.namespace}.svc.cluster.local"
        @log.info "Found ingress #{svc_name} LB(ip=#{svc.status.loadBalancer.ingress})" 
        
        svc.status.loadBalancer.ingress.each do |lb|
          addr = lb.ip || lb.hostname
          @ingresses[addr] = create_proxy(addr,svc_name)
          known.delete(addr)
        end
      end
    end

    known.each do |k|
      remove_proxy(k)
    end
  end

  def main_loop
    etchosts_path = nil

    OptionParser.new { |opts|
      opts.on("--namespace NS", "Namespace to create proxy deployments in") { |ns| @namespace = ns}
      opts.on("--etc-hosts ETCHOSTSPATH", "Path to writable /etc/hosts file") do |h|
        etchosts_path = h
        raise "File #{etchosts_path} doesn't exist!" unless File.exist?(etchosts_path)
        raise "File #{etchosts_path} isn't writable!" unless File.writable?(etchosts_path)
      end
      opts.on("--dry-run", "Do not make any changes, output proxy and coredns configuration changes") do
        @dry_run = true 
        @log.info "Running in dry-run mode!"
      end
      # TODO Make supported API-Versions for ingeresses configurable
    }.parse!

    if etchosts_path && etchosts_path != ""
      @log.info("Starting in /etc/hosts mutation mode on #{etchosts_path}. (Intended to be run as a DaemonSet: one instance per Node.)")
    else
      etchosts_path = nil
      @log.info("Starting in CoreDNS mode. (Indended to be run as a Deployment: one instance per cluster.)")
    end

    @log.info("Starting main_loop with #{POLL_INTERVAL}s polling interval.")
    loop do
      find_ingresses

      if etchosts_path.nil?
        check_and_rewrite_coredns
      else
        check_and_rewrite_etchosts(etchosts_path)
      end

      sleep(POLL_INTERVAL)
    end
  end
end

HairpinProxyController.new.main_loop if $PROGRAM_NAME == __FILE__
