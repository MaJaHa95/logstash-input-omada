# encoding: utf-8
require "logstash/inputs/base"
require "stud/interval"
require "socket" # for Socket.gethostname
require "json"
require "date"

# Generate a repeating message.
#
# This plugin is intented only as an example.

OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE

class OmadaInstance
  def initialize(host, ssl, username, password)
    if ssl
      @session = Net::HTTP.start(host, 443, use_ssl: true)
    else
      @session = Net::HTTP.start(host, 80)
    end

    @cookies = nil
    
    @username = username
    @password = password

    @omadacId = nil
    @token = nil
  end

  def get_omadacid
    unless @omadacId
      info = self.get_info
      @omadacId = info["omadacId"]
    end

    return @omadacId
  end

  def get_token
    unless @token
      omadacid = self.get_omadacid

      url = "/#{omadacid}/api/v2/login"

      req = Net::HTTP::Post.new(url)
      req.body = JSON.generate({
        username: @username,
        password: @password.value
      })
      req["Content-Type"] = "application/json"
      
      resp = @session.request(req)

      @cookies = resp["Set-Cookie"]

      resp_json = JSON.parse(resp.body)

      @token = resp_json["result"]["token"]
    end

    return @token
  end

  def get_url(path, query_parameters = nil)
    unless path.start_with?("/")
        path = "/" + path
    end

    omadacid = self.get_omadacid

    url = URI("/" + omadacid + path)

    if query_parameters
        url.query = URI.encode_www_form(query_parameters)
    end

    return url.to_s
  end

  def send_request(req)
    req["Accept"] = "application/json"
    req["Csrf-Token"] = self.get_token
    req["Cookie"] = @cookies

    resp = @session.request(req)

    resp_json = JSON.parse(resp.body)

    error_code = resp_json["errorCode"]

    unless error_code == 0
        raise "invalid response from '#{req.uri}': " + resp.body
    end

    return resp_json["result"]
  end

  def enumerate_pages(path)
    max_page = 1
    per_page = 100
    
    results = []
    
    page = 0
    while page < max_page
      page = page + 1
      
      query_parameters = {
          "currentPage": page,
          "currentPageSize": per_page
      }

      result = self.send_request(Net::HTTP::Get.new(self.get_url(path, query_parameters)))

      total_rows = result["totalRows"]
      max_page = (total_rows / per_page).to_int + 1
      
      results.concat(result["data"])
    end

    return results
  end

  def get_info
    
    req = Net::HTTP::Get.new("/api/info")
      
    resp = @session.request(req)

    resp_json = JSON.parse(resp.body)

    return resp_json["result"]
  end

  def get_current_user
    resp = self.send_request(Net::HTTP::Get.new(self.get_url("/api/v2/users/current")))

    return resp
  end
  
  def get_sites
    current_user = self.get_current_user

    current_user["privilege"]["sites"].map { |site|
      OmadaSite.new(self, site["key"], site["name"])
    }
  end

  def dispose
    @session.finish
  end
end

class OmadaSite
  def initialize(omada_instance, site_key, site_name)
    @omada_instance = omada_instance
    @site_key = site_key
    @site_name = site_name
  end

  def get_site_name
    return @site_name
  end

  def get_site_key
    return @site_key
  end

  def get_url(subpath, query_parameters = nil)
    unless subpath.start_with?("/")
        subpath = "/" + subpath
    end
    
    return @omada_instance.get_url("/api/v2/sites/" + @site_key + subpath, query_parameters)
  end
  
  def send_request(req)
    resp = @omada_instance.send_request(req)

    return resp
  end

  def enumerate_pages(subpath)
    unless subpath.start_with?("/")
        subpath = "/" + subpath
    end
    
    return @omada_instance.enumerate_pages("/api/v2/sites/" + @site_key + subpath)
  end

  def get_all_clients
    return self.enumerate_pages("/clients")
  end

  def get_all_devices
    result = self.send_request(Net::HTTP::Get.new(self.get_url("/devices")))

    return result
  end

  def get_all_events
    return self.enumerate_pages("/events")
  end

  def get_client_distribution
    return self.send_request(Net::HTTP::Get.new(self.get_url("/dashboard/clientsFreqDistribution")))
  end

  def get_association_failure_statistics
    return self.send_request(Net::HTTP::Get.new(self.get_url("/dashboard/associationFailures")))
  end

  def get_latest_isp_load(to = nil, from = nil)
    unless to
      to = DateTime.now
    end

    unless from
      from = to - 1
    end

    resp = self.send_request(Net::HTTP::Get.new(self.get_url("/dashboard/ispLoad", {
      start: from.to_time.to_i,
      end: to.to_time.to_i
    })))

    ret = []
    resp.each { |port|
        last = port["data"].last

        if last
            ret.append({
                port: {
                    id: port["portId"],
                    name: port["portName"]
                },
                totalRate: last["totalRate"],
                latency: last["latency"],
                time: last["time"]
            })
        end
    }

    return ret
  end

  def get_latest_speed_tests(to = nil, from = nil)
    unless to
      to = DateTime.now
    end

    unless from
      from = to - 1
    end

    req = Net::HTTP::Post.new(self.get_url("/stat/wanSpeeds"))
    req.body = JSON.generate({
      start: from.to_time.to_i,
      end: to.to_time.to_i
    })
    req["Content-Type"] = "application/json"
    
    resp = self.send_request(req)

    last = resp.last
    
    ret = []
    
    if last
      last["ports"].each { |port|
        ret.append({
          time: last["time"],
          port: {
              id: port["portId"],
              name: port["name"]
          },
          latencyMs: port["latency"],
          downloadBandwidthMbps: port["down"],
          uploadBandwidthMbps: port["up"]
        })
      }
    end

    return ret
  end
end

class LogStash::Inputs::Omada < LogStash::Inputs::Base
  config_name "omada"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "plain"

  # The host string to use in the event.
  config :server, :validate => :string
  config :ssl, :validate => :boolean

  config :username, :validate => :string
  config :password, :validate => :password

  # Set how frequently messages should be sent.
  #
  # The default, `60`, checks once a minute.
  config :interval, :validate => :number, :default => 60

  private
  def get_site_hash(site)
    return {
      name: site.get_site_name,
      key: site.get_site_key
    }
  end
  
  def apply_association_failure_statistics(site, queue)
    association_failure_statistics = site.get_association_failure_statistics
    
    site_hash = get_site_hash(site)
    
    omada = {
        site: site_hash,
        associationFailureStatistics: association_failure_statistics
    }
    
    event = LogStash::Event.new("omada" => omada, "tags" => ["omada.association_failure_statistics"])
    decorate(event)
    queue << event
  end

  def apply_latest_isp_load(site, queue)
    now = DateTime.now

    isp_load_ports = site.get_latest_isp_load(now, @next_isp_load_since)

    unless isp_load_ports.empty?
      @next_isp_load_since = now
      
      site_hash = get_site_hash(site)
      
      isp_load_ports.each { |isp_load_port|
          omada = {
            site: site_hash,
            ispLoad: isp_load_port
          }
          
          timestamp = Time.at(isp_load_port.delete(:time)).utc.iso8601
          
          event = LogStash::Event.new("@timestamp" => timestamp, "omada" => omada, "tags" => ["omada.isp_load"])
          decorate(event)
          queue << event
      }
    end
  end

  def apply_latest_speed_tests(site, queue)
    now = DateTime.now

    speed_test_ports = site.get_latest_speed_tests(now, @next_speed_tests_since)
    
    unless speed_test_ports.empty?
      @next_speed_tests_since = now
      
      site_hash = get_site_hash(site)
      
      speed_test_ports.each { |speed_test_port|
          omada = {
            site: site_hash,
            speedTest: speed_test_port
          }

          timestamp = Time.at(speed_test_port.delete(:time)).utc.iso8601
          
          event = LogStash::Event.new("@timestamp" => timestamp, "omada" => omada, "tags" => ["omada.speed_test"])
          decorate(event)
          queue << event
      }
    end
  end
  
  def apply_client_distribution(site, queue)
    site_hash = get_site_hash(site)

    client_distribution = site.get_client_distribution
    
    omada = {
      site: site_hash,
      clientDistribution: client_distribution
    }
    
    event = LogStash::Event.new("omada" => omada, "tags" => ["omada.client_distribution"])
    decorate(event)
    queue << event
  end
  
  def apply_devices(site, queue)
    site_hash = get_site_hash(site)

    site.get_all_devices.each { |device|
        omada = {
          site: site_hash,
          device: device
        }
        
        event = LogStash::Event.new("omada" => omada, "tags" => ["omada.device"])
        decorate(event)
        queue << event
    }
  end
  
  def apply_clients(site, queue)
    site_hash = get_site_hash(site)
    
    site.get_all_clients.each { |client|
        omada = {
          site: site_hash,
          client: client
        }
        
        event = LogStash::Event.new("omada" => omada, "tags" => ["omada.client"])
        decorate(event)
        queue << event
    }
  end
  
  public
  def register
    @host = Socket.gethostname

    @logger.info("Connecting to Omada API", :server => @server)
    @omada_instance = OmadaInstance.new(@server, @ssl, @username, @password)
  end # def register

  def run(queue)
    # we can abort the loop if stop? becomes true
    while !stop?
      @omada_instance.get_sites.each { |site|
        apply_clients(site, queue)
        apply_devices(site, queue)
        apply_client_distribution(site, queue)
        apply_association_failure_statistics(site, queue)
        apply_latest_isp_load(site, queue)
        apply_latest_speed_tests(site, queue)
      }

      # because the sleep interval can be big, when shutdown happens
      # we want to be able to abort the sleep
      # Stud.stoppable_sleep will frequently evaluate the given block
      # and abort the sleep(@interval) if the return value is true
      Stud.stoppable_sleep(@interval) { stop? }
    end # loop
  end # def run

  def stop
    @omada_instance.dispose
  end
end # class LogStash::Inputs::Omada
