# HR's Custom ShodanAPI Class, tweaked for creep3r ;)
class ShodanAPI
  # Initialize ShodanAPI via passed API Key
  def initialize(apikey)
    @http=EasyCurb.new
    @url="http://www.shodanhq.com/api/"
    if shodan_connect(apikey)
      @key=apikey
    end
  end

  # Check API Key against API Info Query
  # Return True on success, False on Error or Failure
  def shodan_connect(apikey)
    url = @url + "info?key=#{apikey}"
    res = @http.get(url)
    if res[0] =~ /"unlocked_left": \d+, "telnet": .+, "plan": ".+", "https": .+, "unlocked": .+/i
      results = JSON.parse(res[0])
      @plan = results['plan']
      @unlocked = results['unlocked']
      @unlocks = results['unlocked_left']
      @https = results['https']
      @telnet = results['telnet']
      return true
    elsif res[0] =~ /"error": "API access denied"/i
      print_error("Access Denied using API Key '#{apikey}'")
      print_error("Check Key & Try Again....")
      return false
    else
      print_error("Unknown Problem with Connection to Shodan API!")
      return false
    end
  end

  # Just checks our key is working (re-using shodan_connect so updates @unlocks)
  # Returns True or False
  def connected?
    return false if @key.nil?
    if shodan_connect(@key)
      return true
    else
      return false
    end
  end

  # Return the number of unlocks remaining
  def unlocks
    if shodan_connect(@key)
      return @unlocks.to_i
    else
      return nil
    end
  end

  # Check if HTTPS is Enabled
  def https?
    if shodan_connect(@key)
      if @https
        return true
      else
        return false
      end
    else
      return false
    end
  end

  # Check if Telnet is Enabled
  def telnet?
    if shodan_connect(@key)
      if @telnet
        return true
      else
        return false
      end
    else
      return false
    end
  end

  # Actually display Basic Info for current API Key
  def info
    url = @url + 'info?key=' + @key
    res = @http.get(url)
    if res[0].nil? or res[0] == ''
      print_error("Unknown Problem fetching API Key info!")
      return false
    else
      results = JSON.parse(res[0])
      puts
      print_good("Shodan API Key Confirmed!")
      print_good("API Key: #{@key}")
      print_good("Plan Type: #{results['plan']}")
      print_good("Unlocked: #{results['unlocked']}")
      print_good("Unlocks Remaining: #{results['unlocked_left']}")
      print_good("HTTPS Enabled: #{results['https']}")
      print_good("Telnet Enabled: #{results['telnet']}")
      return true
    end
  end

  # Lookup all available information for a specific IP address
  # Returns results hash or nil
  def host(ip)
    url = @url + 'host?ip=' + ip + '&key=' + @key
    res = @http.get(url)
    if res[0].nil? or res[0] == ''
      print_error("Problem running Host Search or No Results Found!")
      return nil
    else
      results = JSON.parse(res[0])
      return results
    end
  end

  # Returns the number of devices that a search query found
  # Unrestricted usage of all advanced filters
  # Return results count or nil on failure
  def count(string)
    url = @url + 'count?q=' + string + '&key=' + @key
    res = @http.get(url)
    if res[0].nil? or res[0] == ''
      print_error("Problem grabbing results count!")
      return nil
    else
      results = JSON.parse(res[0])
      return results['total']
    end
  end

  # Search Shodan for devices using a search query
  # Returns results hash or nil
  def search(string, filters={})
    prem_filters =  [ 'city', 'country', 'geo', 'net', 'before', 'after', 'org', 'isp', 'title', 'html' ]
    cheap_filters = [ 'hostname', 'os', 'port' ]
    url = @url + 'search?q=' + string
    if not filters.empty?
      filters.each do |k, v|
        if cheap_filters.include?(k)
          url += ' ' + k + ":\"#{v}\""
        end
        if prem_filters.include?(k)
          if @unlocks.to_i > 1
            url += ' ' + k + ":\"#{v}\""
            @unlocks = @unlocks.to_i - 1 # Remove an unlock for use of filter
          else
            puts "Not Enough Unlocks Left to run Premium Filter Search".light_red + "!".white
            puts "Try removing '#{k}' filter and trying again".light_red + "....".white
            return nil
          end
        end
      end
    end
    url += '&key=' + @key
    res = @http.get(url)
    if res[0].nil? or res[0] == ''
      print_error("Problem running Shodan Search or No Results Found!")
      return nil
    else
      results = JSON.parse(res[0])
      return results
    end
  end

  # Quick Search Shodan for devices using a search query
  # Results are limited to only the IP addresses
  # Returns results array or nil
  def quick_search(string, filters={})
    prem_filters =  [ 'city', 'country', 'geo', 'net', 'before', 'after', 'org', 'isp', 'title', 'html' ]
    cheap_filters = [ 'hostname', 'os', 'port' ]
    url = @url + 'search?q=' + string
    if not filters.empty?
      filters.each do |k, v|
        if cheap_filters.include?(k)
          url += ' ' + k + ":\"#{v}\""
        end
        if prem_filters.include?(k)
          if @unlocks.to_i > 1
            url += ' ' + k + ":\"#{v}\""
            @unlocks = @unlocks.to_i - 1
          else
            puts "Not Enough Unlocks Left to run Premium Filter Search".light_red + "!".white
            puts "Try removing '#{k}' filter and trying again".light_red + "....".white
            return nil
          end
        end
      end
    end
    url += '&key=' + @key
    res = @http.get(url)
    if res[0].nil? or res[0] == ''
      print_error("Problem running Shodan Search or No Results Found!")
      return nil
    else
      ips=[]
      results = JSON.parse(res[0])
      results['matches'].each do |host|
       ips << host['ip']
      end
      return ips
    end
  end

  # Perform Shodan Exploit Search as done on Web
  # Provide Search String and source
  # Source can be: metasploit, exploitdb, or cve
  # Returns results hash array on success: { downloadID => { link => description } }
  # Returns nil on failure
  def sploit_search(string, source)
    sources = [ "metasploit", "exploitdb", "cve" ]
    if sources.include?(source.downcase)
      results={}
      sploits = 'https://exploits.shodan.io/?q=' + string + ' source:"' + source.downcase + '"'
      res = @http.get(sploits)
      page = Nokogiri::HTML(res[0]) # Parsable doc object now

      # Enumerate target section, parse out link & description
      page.css('div[class="search-result well"]').each do |linematch|
        if linematch.to_s =~ /<div class="search-result well">\s+<a href="(.+)"\s/
          link=$1
        end
        if linematch.to_s =~ /class="title">(.+)\s+<\/a>/
          desc=$1.gsub('<em>', '').gsub('</em>', '')
        end
        case source.downcase
        when 'cve'
          dl_id = 'N/A for CVE Search'
        when 'exploitdb'
          dl_id = link.split('/')[-1] unless link.nil?
        when 'metasploit'
          dl_id = link.sub('http://www.metasploit.com/', '').sub(/\/$/, '') unless link.nil?
        end
        results.store(dl_id, { link => desc}) unless (link.nil? or link == '') or (desc.nil? or desc == '') or (dl_id.nil? or dl_id == 'N/A for CVE Search')
      end
      return results
    else
      print_error("Invalid Search Source Requested!")
      return nil
    end
  end

  # Download Exploit Code from Exploit-DB or MSF Github Page
  # By passing in the Download ID (which can be seen in sploit_search() results)
  # Return { 'Download' => dl_link, 'Viewing' => v_link, 'Exploit' => res[0] }
  # or nil on failure
  def sploit_download(id, source)
    sources = [ "metasploit", "exploitdb" ]
    if sources.include?(source.downcase)
      case source.downcase
      when 'exploitdb'
        dl_link = "http://www.exploit-db.com/download/#{id}/"
        v_link = "http://www.exploit-db.com/exploits/#{id}/"
      when 'metasploit'
        dl_link = "https://raw.github.com/rapid7/metasploit-framework/master/#{id.sub('/exploit/', '/exploits/')}.rb"
        v_link = "http://www.rapid7.com/db/#{id}/"
      end
      res = @http.get(dl_link)
      page = Nokogiri::HTML(res[0]) # Parsable doc object now
      results = { 'Download' => dl_link, 'Viewing' => v_link, 'Exploit' => res[0] }
      return results
    else
      print_error("Invalid Download Source Requested!")
      return false
    end
  end
end
