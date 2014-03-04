# Help Menu
def login_tools_help
  puts "Available Options from Recon Menu: ".underline.white
  puts "back".light_yellow + "   => ".white + "Return to Main Menu".light_red
  puts "ftp".light_yellow + "    => ".white + "FTP Service Login".light_red
  puts "ssh".light_yellow + "    => ".white + "SSH Service Login".light_red
  puts "mssql".light_yellow + "  => ".white + "MS-SQL Service Login".light_red
  puts "mysql".light_yellow + "  => ".white + "MySQL Service Login".light_red
  puts "pgsql".light_yellow + "  => ".white + "Postgres Service Login".light_red
  puts "snmp".light_yellow + "   => ".white + "SNMP Service Login".light_red
  puts "telnet".light_yellow + " => ".white + "Telnet Service Login".light_red
  puts
end

def login_tools_menu
  puts
  prompt = "(log1n)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      login_tools_menu
    when /^c$|^clear$|^cls$/i
      cls
      banner
      login_tools_menu
    when /^h$|^help$|^ls$/i
      puts
      login_tools_help
      login_tools_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^local$|^OS$/i
      local_shell
      login_tools_menu
    when  /^ip$/i
      ip_info
      login_tools_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      login_tools_menu
    when  /^FTP$/i
      ssb = SSB.new()
      target = Readline.readline("   Enter Target IP: ", true)
      username = Readline.readline("   Enter Username: ", true)
      while(true)
        wordlist = Readline.readline("   Wordlist to Use: ", true)
        puts
        if File.exists?(wordlist.strip.chomp)
          break
        else
          puts
          print_error("Unable to load wordlist file!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      print_status("Attempting FTP Login to: #{target.strip.chomp}")
      passwords = File.open(wordlist.strip.chomp).readlines
      ssb.ftp_anon_check(target.strip.chomp)
      puts
      ssb.slow_brute('FTP', target.strip.chomp, username.strip.chomp, passwords)
      login_tools_menu
    when  /^SSH$/i
      ssb = SSB.new()
      target = Readline.readline("   Enter Target IP: ", true)
      answer = Readline.readline("   Use Default SSH Port 22 (Y/N)?: ", true)
      if answer[0].upcase == 'N'
        ssh_port = Readline.readline("   Enter Port: ", true)
        ssb.set_service_port('SSH', ssh_port.strip.chomp.to_i)
      end
      username = Readline.readline("   Enter Username: ", true)
      while(true)
        wordlist = Readline.readline("   Wordlist to Use: ", true)
        puts
        if File.exists?(wordlist.strip.chomp)
          break
        else
          puts
          print_error("Unable to load wordlist file!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      print_status("Attempting SSH Login to: #{target.strip.chomp}")
      passwords = File.open(wordlist.strip.chomp).readlines
      ssb.slow_brute('SSH', target.strip.chomp, username.strip.chomp, passwords)
      login_tools_menu
    when  /^MS.SQL$|^mssql$/i
      ssb = SSB.new()
      target = Readline.readline("   Enter Target IP: ", true)
      answer = Readline.readline("   Use Default MS-SQL Port 1433 (Y/N)?: ", true)
      if answer[0].upcase == 'N'
        mssql_port = Readline.readline("   Enter Port: ", true)
        ssb.set_service_port('MSSQL', mssql_port.strip.chomp.to_i)
      end
      username = Readline.readline("   Enter Username: ", true)
      while(true)
        wordlist = Readline.readline("   Wordlist to Use: ", true)
        puts
        if File.exists?(wordlist.strip.chomp)
          break
        else
          puts
          print_error("Unable to load wordlist file!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      print_status("Attempting MS-SQL Login to: #{target.strip.chomp}")
      passwords = File.open(wordlist.strip.chomp).readlines
      ssb.slow_brute('MSSQL', target.strip.chomp, username.strip.chomp, passwords)
      login_tools_menu
    when  /^MySQL$/i
      ssb = SSB.new()
      target = Readline.readline("   Enter Target IP: ", true)
      answer = Readline.readline("   Use Default MySQL Port 3306 (Y/N)?: ", true)
      if answer[0].upcase == 'N'
        mysql_port = Readline.readline("   Enter Port: ", true)
        ssb.set_service_port('MYSQL', mysql_port.strip.chomp.to_i)
      end
      username = Readline.readline("   Enter Username: ", true)
      while(true)
        wordlist = Readline.readline("   Wordlist to Use: ", true)
        puts
        if File.exists?(wordlist.strip.chomp)
          break
        else
          puts
          print_error("Unable to load wordlist file!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      print_status("Attempting MySQL Login to: #{target.strip.chomp}")
      passwords = File.open(wordlist.strip.chomp).readlines
      ssb.slow_brute('MYSQL', target.strip.chomp, username.strip.chomp, passwords)
      login_tools_menu
    when  /^Postgres|^pg$|^pgsql$/i
      ssb = SSB.new()
      target = Readline.readline("   Enter Target IP: ", true)
      answer = Readline.readline("   Use Default Postgres Port 5432 (Y/N)?: ", true)
      if answer[0].upcase == 'N'
        pgsql_port = Readline.readline("   Enter Port: ", true)
        ssb.set_service_port('PGSQL', pgsql_port.strip.chomp.to_i)
      end
      username = Readline.readline("   Enter Username: ", true)
      while(true)
        wordlist = Readline.readline("   Wordlist to Use: ", true)
        puts
        if File.exists?(wordlist.strip.chomp)
          break
        else
          puts
          print_error("Unable to load wordlist file!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      print_status("Attempting Postgres Login to: #{target.strip.chomp}")
      passwords = File.open(wordlist.strip.chomp).readlines
      ssb.slow_brute('PGSQL', target.strip.chomp, username.strip.chomp, passwords)
      login_tools_menu
    when  /^SNMP$/i
      ssb = SSB.new()
      target = Readline.readline("   Enter Target IP: ", true)
      username = Readline.readline("   Enter Username: ", true)
      while(true)
        wordlist = Readline.readline("   Wordlist to Use: ", true)
        puts
        if File.exists?(wordlist.strip.chomp)
          break
        else
          puts
          print_error("Unable to load wordlist file!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      print_status("Host: #{target.strip.chomp}:161")
      print_status("Service: SNMP")
      passwords = File.open(wordlist.strip.chomp).readlines
      ssb.snmp_brute(target.strip.chomp, passwords)
      login_tools_menu
    when  /^Telnet$/i
      ssb = SSB.new()
      target = Readline.readline("   Enter Target IP: ", true)
      answer = Readline.readline("   Use Default Telnet Port 23 (Y/N)?: ", true)
      if answer[0].upcase == 'N'
        telnet_port = Readline.readline("   Enter Port: ", true)
        ssb.set_service_port('TELNET', telnet_port.strip.chomp.to_i)
      end
      username = Readline.readline("   Enter Username: ", true)
      while(true)
        wordlist = Readline.readline("   Wordlist to Use: ", true)
        puts
        if File.exists?(wordlist.strip.chomp)
          break
        else
          puts
          print_error("Unable to load wordlist file!")
          print_error("Check path or permissions and try again....\n\n")
        end
      end
      print_status("Attempting Telnet Login to: #{target.strip.chomp}")
      passwords = File.open(wordlist.strip.chomp).readlines
      ssb.slow_brute('TELNET', target.strip.chomp, username.strip.chomp, passwords)
      login_tools_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      login_tools_menu
    end
  end
end
