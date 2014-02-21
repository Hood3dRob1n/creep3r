# MS-SQL Menu

def ms_sql_usage
  puts "Available MS-SQL SQLi Options: ".underline.white
  puts "clear".light_yellow + "   => ".white + "Clear Terminal".light_red
  puts "back".light_yellow + "    => ".white + "Return to Main Menu".light_red
  puts "test".light_yellow + "    => ".white + "MS-SQL Link Tester".light_red
  puts "blind".light_yellow + "   => ".white + "MS-SQL Blind Injection Tool".light_red
  puts "union".light_yellow + "   => ".white + "MS-SQL Union Injection Tool".light_red
  puts "time".light_yellow + "    => ".white + "MS-SQL Time Based Injection Tool".light_red
  puts "error".light_yellow + "   => ".white + "MS-SQL Error Based Injection Tool".light_red
  puts "stacked".light_yellow + " => ".white + "MS-SQL Stacked Queries Injection Tool".light_red
  puts
end

def ms_sql_menu
  puts
  prompt = "(MS-SQL)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      ms_sql_menu
    when /^h$|^help$|^ls$/i
      puts
      ms_sql_usage
      ms_sql_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      ms_sql_menu
    when /^local$|^OS$/i
      local_shell
      ms_sql_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      ms_sql_menu
    when /^ip$/i
      ip_info
      ms_sql_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      ms_sql_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      ms_sql_menu
    end
  end
end
