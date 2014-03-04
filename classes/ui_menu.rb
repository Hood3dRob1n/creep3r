# Help Menu
def main_menu_help
  puts "Available Options: ".underline.white
  puts "clear".light_yellow + "     => ".white + "Clear Terminal".light_red
  puts "exit".light_yellow + "      => ".white + "Exit Session".light_red
  puts "ip".light_yellow + "        => ".white + "Internal & Exnternal IP".light_red
  puts "config".light_yellow + "    => ".white + "Current Config Settings".light_red
  puts "dork".light_yellow + "      => ".white + "Search & Dork Tools".light_red
  puts "recon".light_yellow + "     => ".white + "Recon Tools".light_red
  puts "include".light_yellow + "   => ".white + "File Include Tool".light_red
  puts "sqli".light_yellow + "      => ".white + "SQLi Testing Tools".light_red
  puts "dbtools".light_yellow + "   => ".white + "Database Tools".light_red
  puts "special".light_yellow + "   => ".white + "Specialty Tools".light_red
  puts "passwords".light_yellow + " => ".white + "Password Tools".light_red
  puts "login".light_yellow + "     => ".white + "Service Login Tools".light_red
  puts "listener".light_yellow + "  => ".white + "Listners & Connectors".light_red
  puts "payloads".light_yellow + "  => ".white + "Simple Payload Tools".light_red
  puts "strass".light_yellow + "    => ".white + "String Assistant Tool".light_red
  puts "local".light_yellow + "     => ".white + "Local OS Shell".light_red
  puts "console".light_yellow + "   => ".white + "Interactive Ruby Console".light_red
  puts
end

# Main Menu for CLI App
def main_menu
  puts
  prompt = "(creep3r)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      main_menu
    when /^h$|^help$|^ls$/i
      puts
      main_menu_help
      main_menu
    when /^exit$|^quit$/i
      puts
      print_error("OK, cleaning up and exiting....\n\n")
      begin
        exit
      rescue ArgumentError
      end
    when /^local$|^OS$/i
      local_shell
      main_menu
    when /^console$|^irb$/i
      print_status("Dropping to Ruby console....\n")
      IRB.start_session(binding)
      main_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      main_menu
    when /^search$|^dork$/i
      search_menu
      main_menu
    when /^recon$|^dnsenum$|^nmap$/i
      recon_menu
      main_menu
    when /^include|^lfi$|^rfi$/i
      includer_menu
      main_menu
    when /^dbtools$/i
      dbtools_menu
      main_menu
    when /^special/i
      special_menu
      main_menu
    when  /^ip$/i
      ip_info
      main_menu
    when  /^sqli$/i
      puts
      while(true)
        print_caution("Available SQLi Menu Options: ")
        print_caution("0) Back to Main Menu")
        print_caution("1) MySQL Injector Menu")
#        print_caution("2) MS-SQL Injector Menu")
#        print_caution("3) MS-Access Injector Menu")
        option = Readline.readline("   Enter Option: ", true)
        puts
        if option.to_s.chomp.to_i >= 0 and option.to_s.chomp.to_i <= 3
          case option.to_s.chomp.to_i
          when 0
            print_error("OK, Returning to Main Menu...\n")
            main_menu
          when 1
            print_status("OK, routing to MySQL Injector Menu...")
            mysql_menu
          when 2
            print_status("OK, routing to MS-SQL Injector Menu...")
            ms_sql_menu
          when 3
            print_status("OK, routing to MS-Access Injector Menu...")
            ms_access_menu
          end
          break
        else
          puts
          print_error("Invalid Selection!")
          print_error("Please choose a valid option from menu below\n\n")
        end
      end
      main_menu
    when /^password|^wordlist|^pass$/i
      password_menu
      main_menu
    when /^strass$|^string.assist|^strings$/i
      strass_menu
      main_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      main_menu
    when /^!(.+)/
      # Execute system commands in terminal
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      main_menu
    when /^login|^service.brute|^bruter$/i
      login_tools_menu
      main_menu
    when /^listen|^connect$/i
      listener_menu
      main_menu
    when /^payload/i

      main_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      main_menu
    end
  end
end

# Local OS Pseudo shell
def local_shell
  cls
  banner
  puts "\n\n"
  prompt = "(Local)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^exit$|^quit$|^back$/i
      print_error("OK, Returning to Main Menu....")
      break
    else
      begin
        rez = commandz(cmd) # Run command passed
        puts rez.join().white #print results nicely for user....
      rescue => e
        puts
        print_error(e.to_s + "\n\n")
      end
    end
  end
end
