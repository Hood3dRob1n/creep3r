# HTTP Request Class & Associated Functions

# Return random user-agent string
def user_agent_str
  agents = [
  'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)',
  'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
  'Mozilla/5.0 (X11; CrOS i686 4319.74.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.57 Safari/537.36',
  'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/20121202 Firefox/17.0 Iceweasel/17.0.1',
  'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)',
  'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)',
  'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
  'Mozilla/5.0 (compatible; Konqueror/4.5; FreeBSD) KHTML/4.5.4 (like Gecko)',
  'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00' ]
  return agents[rand(agents.size)]
end

# Find the parameters in passed URL or Post Data String
# Uses '&' and '=' characters to mark key|value pairs
# Returns a Hash{ 'param' => 'value' } with the results
def find_parameters(paramaterstring)
  parameters={}
  if not paramaterstring =~ /.+=/
    return nil
  else
    if paramaterstring =~ /.+=.+&.+/
      foo = paramaterstring.split('&')
      foo.each do |paramz|
        parameters.store(paramz.split('=')[0], paramz.split('=')[1])
      end
      return parameters
    elsif paramaterstring =~ /.+=.+;.+/
      foo = paramaterstring.split(';')
      foo.each do |paramz|
        parameters.store(paramz.split('=')[0], paramz.split('=')[1])
      end
      return parameters
    else
      k = paramaterstring.split('=')[0]
      v = paramaterstring.split('=')[1]
      parameters.store(k, v)
      return parameters
    end
  end
end

# Take given link and mod it with possible injections
# return array of new potential testing links
def link_changer(link, parameters=nil)
  links=[]
  trav='..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2f.%2f.%2fpasswd%00' # Should work for 99% of LFI and bypass outdated ModSec rules as well
  case $config['DORKER']['TESTS'].to_i
  when 0
    if parameters.nil?
      # No parameter test
      if link =~ /\/$/
        links << link.sub(/\/$/, "'/")
      else
        links << "#{link}'"
      end
    else
      # parameter test
      parameters.each do |k, v|
        links << link.sub("#{k}=#{v}", "#{k}=#{v}'") # Inject into each parameter value
      end
    end
  when 1
    if parameters.nil?
      # No parameter test
      if link =~ /\/$/
        links << link.sub(/\/$/, "#{trav}/")
      else
        links << "#{link}#{trav}"
      end
    else
      # parameter test
      parameters.each do |k, v|
        links << link.sub("#{k}=#{v}", "#{k}=#{v}#{trav}")
      end
    end
  when 2
    if parameters.nil?
      # No parameter test
      if link =~ /\/$/
        links << link.sub(/\/$/, "'/")
        links << link.sub(/\/$/, "#{trav}/")
      else
        links << "#{link}'"
        links << "#{link}#{trav}"
      end
    else
      # parameter test
      parameters.each do |k, v|
        links << link.sub("#{k}=#{v}", "#{k}=#{v}'")
        links << link.sub("#{k}=#{v}", "#{k}=#{v}#{trav}")
      end
    end
  end

  return links.uniq
end

# Prep Links for injection tests
# Return array of all the prepped links when done
def link_prep(arrayoflinks)
  puts "[".light_green + "*".white + "]".light_green + " Prepping links for testing....".white
  testlinks=[]
  arrayoflinks.each do |link|
    paras = link.split('?')[1]
    if paras.nil?
      lnkz = link_changer(link)
      lnkz.each { |x| testlinks << x }
    else
      parameters = find_parameters(paras)
      lnkz = link_changer(link, parameters)
      lnkz.each { |x| testlinks << x }
    end
  end
  return testlinks.uniq
end

# Send requests using prepped links
# Test response bodies for signs of possible injection
# Report back positive findings
def send_and_check(arrayoflinks)
  puts "[".light_green + "*".white + "]".light_green + " Sending Injection requests, hang tight this might take a few....".white
  http=EasyCurb.new()
  $config['HTTP']['PROGRESS'] = true        # Enable progressbar
  mresponses = http.multi_get(arrayoflinks) # Curl Multi Mode
  $config['HTTP']['PROGRESS'] = false       # Disable progressbar
  puts "\n[".light_green + "*".white + "]".light_green + " Running Response Checks now....\n".white
  arrayoflinks.each do |url|
    quick_regex_check(url, mresponses[url].body_str) # Vuln Check against Response Bodies
  end
  puts
  print_status("Testing Complete")
  print_status("Hope you found what you were looking for :)")
end

# Curb Wrapper Class
# Helps with actual HTTP Request Handling
# Makes MY life easier so take it or leave it
class EasyCurb
  # Curl::Multi Request Option
  # Returns a Hash { 'url link' => [single curb response array] }
#        url                                     # URL
#        mresponses[url].body_str                # Response Body
#        mresponses[url].response_code           # Response Code
#        mresponses[url].header_str              # Response Header String
#        mresponses[url].total_time.to_s[0..5]   # Response Time
  def multi_get(arrayoflinks)
    mresponses = {}
    m = Curl::Multi.new

    # Get our progress bar going if needed
    if $config['HTTP']['PROGRESS']
      @progressbar = ProgressBar.create(:title => "   ETA", :starting_at => 0, :total => arrayoflinks.size)
    end

    # Add a few easy handles
    arrayoflinks.each do |url|
      mresponses[url] = simple(url)
      m.add(mresponses[url])
    end

    begin
      m.perform
    rescue Curl::Err::ConnectionFailedError => e
      print_error("Redo - Problem with Network Connection => #{e}")
    rescue Curl::Err::MalformedURLError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::PartialFileError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::GotNothingError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::RecvError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::TimeoutError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::HostResolutionError => e
      print_error("Problem resolving Host Details => #{e}")
    end

    # Return our Hash with URL as Key and Simple Response Array for Value
    return mresponses
  end

  # Simple Stager for Requests
  # Allows us to add in cookies, headers, Referer, UA, etc...
  # Global variables control most options (set at runtime)
  def simple(link, postdata=nil)
    @ch = Curl::Easy.new(link) do |curl|
      curl.ssl_verify_peer = false
      curl.max_redirects = 3

      # Set Proxy Connection Details if needed
      if $config['HTTP']['PROXY']
#        curl.proxy_tunnel = true
        if $config['HTTP']['TOR_PROXY']
          curl.proxy_type='CURLPROXY_SOCKS5' # Change proxy type to Socks5 for ToR use
        end
        curl.proxy_url = $config['HTTP']['PROXY_IP']
        curl.proxy_port = $config['HTTP']['PROXY_PORT'].to_i
        if $config['HTTP']['PROXY_AUTH']
          curl.proxypwd = "#{$config['HTTP']['PROXY_USER']}:#{$config['HTTP']['PROXY_PASS']}"
        end
      end

      # If using progressbar, increment ETA aftter each success
      if $config['HTTP']['PROGRESS']
        curl.on_complete { |easy| @progressbar.increment }
      end

      # Set HTTP Authentication Details if needed
      if $config['HTTP']['HTTP_AUTH']
        curl.http_auth_types = :basic
        curl.username = $config['HTTP']['HTTP_AUTH_USER']
        curl.password = $config['HTTP']['HTTP_AUTH_PASS']
      end

      # Add custom referrer if needed
      if $config['HTTP']['REF']
        curl.headers['Referer'] = $config['HTTP']['REFERER']
      end

      # Add custom headers as needed
      if $config['HTTP']['HTTP_HEADERS_ADD']
        $config['HTTP']['HTTP_HEADERS'].each do |k, v|
          curl.headers["#{k}"] = "#{v}"
        end
      end

      # Add custom cookies if needed
      if $config['HTTP']['COOKIESUPPORT']
        curl.cookies = $config['HTTP']['COOKIEFILE']
      end

      # Set Request Timeout so we dont wait forever
      curl.timeout = $config['HTTP']['TIMEOUT']

      # Set User-Agent to default or whatever was selected
      curl.useragent = $config['HTTP']['HTTP_USER_AGENT']

      # Enable to make a HEAD request!
      if $config['HTTP']['HTTP_HEAD']
        curl.head = true
      end

      # Setup Post Request If needed
      begin
        curl.http_post(link, postdata) if not postdata.nil?
      rescue Curl::Err::ConnectionFailedError => e
        print_error("Redo - Problem with Network Connection => #{e}")
      rescue Curl::Err::MalformedURLError => e
        print_error("Curl Failure => #{e}")
      rescue Curl::Err::PartialFileError => e
        print_error("Curl Failure => #{e}")
      rescue Curl::Err::RecvError => e
        print_error("Curl Failure => #{e}")
      rescue Curl::Err::GotNothingError => e
        print_error("Curl Failure => #{e}")
      rescue Curl::Err::TimeoutError => e
        print_error("Curl Failure => #{e}")
      rescue Curl::Err::HostResolutionError => e
        print_error("Problem resolving Host Details => #{e}")
      end
    end
  end

  # Make GET requests to given link
  # Returns an array filled with the following: 
  # response_body, response_code, repsonse_time, response_headers
  def get(getlink)
    simple(getlink)
    begin
      @ch.perform
    rescue Curl::Err::ConnectionFailedError => e
      print_error("Redo - Problem with Network Connection => #{e}")
    rescue Curl::Err::MalformedURLError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::PartialFileError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::RecvError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::GotNothingError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::TimeoutError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::HostResolutionError => e
      print_error("Problem resolving Host Details => #{e}")
    end
    return @ch.body_str, @ch.response_code, @ch.total_time, @ch.header_str
  end

  # Make POST requests to given link and post data
  # Returns an array filled with the following: 
  # response_body, response_code, repsonse_time, response_headers
  def post(postlink, postdata)
    simple(postlink, postdata)
    return @ch.body_str, @ch.response_code, @ch.total_time, @ch.header_str
  end

  # Make HEAD requests to given link and post data
  # Returns an array filled with the following: 
  # response_body, response_code, repsonse_time, response_headers
  def head(link)
    $head=true
    simple(link)
    $head=false
    begin
      @ch.perform
    rescue Curl::Err::ConnectionFailedError => e
      print_error("Redo - Problem with Network Connection => #{e}")
    rescue Curl::Err::MalformedURLError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::PartialFileError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::RecvError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::GotNothingError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::TimeoutError => e
      print_error("Curl Failure => #{e}")
    rescue Curl::Err::HostResolutionError => e
      print_error("Problem resolving Host Details => #{e}")
    end
    return @ch.body_str, @ch.response_code, @ch.total_time, @ch.header_str
  end
end

# Send a Single HEAD Request to provided link
# Return response results from request
def single_head(link)
  $config['HTTP']['HTTP_HEAD'] = true
  c=EasyCurb.new
  res = c.head(link)
  # res => response_body, response_code, repsonse_time, response_headers
  if res[0] =~ /<title>(.+)<\/title>/i
    title=$1.to_s[0..25]
  else
    title='N/A'
  end
  t = [ [ 'URL', 'TIME', 'CODE', 'TITLE' ], [ link.chomp, res[2].to_s[0..5], res[1], title ] ]
  table = t.to_table(:first_row_is_head => true)
  puts table.to_s
  print_status("Response Headers:")
  print_status("########################################")
  # Chop up the headers from response
  # Helps highlight the common ones
  # Skip the first since its just the response code which we already grabbed above
  res[3].split("\r\n")[1..-1].each do |line|
    if line =~ /^X-Powered-By: .+|^Date: .+|^Expires: .+|^Age: .+|^Cache: .+|^Cache-Control: .+|^Accept-Ranges: .+|^Via: .+|^Set-Cookie: .+|^Content-Type: .+|^P3P: .+|^Server: .+|^X-XSS-Protection: .+|^X-Frame-Options: .+|^Transfer-Encoding: .+|^Content-Language: .+|^Pragma: .+|^Powered.By: .+|^RTSS: .+|^RTS1: .+|^Lite-checkout: .+|^X-EdgeConnect-MidMile-RTT: .+|^X-EdgeConnect-Origin-MEX-Latency: .+|^ETag: .+|^Connection: .+|^Content-Length: .+|^THD-Cache-Key: .+|^Location: .+|^Vary: .+|^CACHED_RESPONSE: .+|^Last-Modified: .+|^X-Akamai-Transformed: .+|^X-Varnish: .+/i
      puts "[*] " .light_blue + "#{line.split(':')[0]}".light_red + ": #{line.split(':')[1..-1].join()}".white
    else
      print_status("#{line}")
    end
  end
  print_status("########################################")
  $config['HTTP']['HTTP_HEAD'] = false
end

# Head request to multiple links
# Summary table provided when done
# includes: url, response time, status code, page title
def multi_head(urls)
  uri = URI.parse(urls[0])
  $config['HTTP']['HTTP_HEAD'] = true
  cookies=[]
  key_headerz=[]
  c=EasyCurb.new
  outdir = "#{RESULTS}recon/#{uri.host}/"
  cookies_file="#{outdir}cookies.txt"
  results_file="#{outdir}buster_results.txt"
  print_good("Loaded #{urls.size} links for testing.....")
  Dir.mkdir("#{RESULTS}recon/") unless File.exists?("#{RESULTS}recon/") and File.directory?("#{RESULTS}recon/")
  Dir.mkdir(outdir) unless File.exists?(outdir) and File.directory?(outdir)
  results = c.multi_get(urls.uniq)
  # Returns a Hash { 'url link' => [single response object] }
  t = [ [ 'URL', 'TIME', 'CODE' ] ]
  results.each do |url, res|
    if not res.header_str.nil? and res.header_str != ''
      res.header_str.split("\r\n")[1..-1].each do |line|
        if line =~ /Set-Cookie: .+/
          f=File.open(cookies_file, 'a+')
          f.puts "URL: " + url.chomp
          f.puts line.chomp + "\n\n"
          f.close
          cookies << line.chomp if not cookies.include?(line.chomp)
        end
        if line =~ /^X-Powered-By: .+|^Server: .+|^Powered.By: .+/i
          key_headerz << line if not key_headerz.include?(line)
        end
      end
    end
    t << [ url.chomp, res.total_time.to_s[0..5], res.response_code ]
  end
  table = t.to_table(:first_row_is_head => true)
  f=File.open(results_file, 'w+')
  f.puts table.to_s
  puts table.to_s
  f.close
  $config['HTTP']['HTTP_HEAD'] = false
  puts
  print_status("Information from Server Headers Encountered: ")
  key_headerz.each do |x|
    puts "   [".light_blue + "-".white + "] ".light_blue + "#{x}".white
  end
end

