# Support Functions for use throughout

# Generate a random aplha string, with length requested
def randz(num)
  (0...num).map{ ('a'..'z').to_a[rand(26)] }.join
end

# Pseudo Random Generator
# I'm no crypto expert, but works for my purposes...
def genkey(num)
  randz(num).wafcap.randnum.randspecial
end

# Simple Printing functions for uniform messaging output
# Normal Output
def print_line(string)
  print "#{string}\n".white
end

# Status update
def print_status(string)
  print "[".light_blue + "*".white + "]".light_blue + " #{string}\n".white
end

# Input or Caution
def print_caution(string)
  print "[".light_yellow + "*".white + "]".light_yellow + " #{string}\n".white
end

# Good/Success
def print_good(string)
  print "[".light_green + "*".white + "]".light_green + " #{string}\n".white
end

# Error
def print_error(string)
  print "[".light_red + "*".white + "]".light_red + " #{string}\n".white
end

# Execute system commands
# Result output returned as an array
def commandz(foo)
  bar = IO.popen("#{foo}")
  foobar = bar.readlines
  return foobar
end

# Execute commands in separate process - ideally in standalone X-window :)
# Example:
# print_status("Launching MSF PSEXEC against #{zIP}:#{zPORT} in a new x-window.....")
# win_psexec="xterm -title 'MSF PSEXEC' -font -*-fixed-medium-r-*-*-18-*-*-*-*-*-iso8859-* -e \"bash -c '#{MSFPATH}/msfconsole -r #{rcfile}'\""
# fireNforget(win_psexec) #Launches in new X-term window....
def fireNforget(command)
  pid = Process.fork
  if pid.nil?
    exec command
  else
    Process.detach(pid)
  end
  return pid
end

# Pass it a directory traversal (or any string) and it will build out
# I use for bulding traversal paths: ('../' * 4) => '../../../../'
def traversal(step, num) 
  step.to_s * num.to_i
end

# Generate MD4 Hash string
def md4(string)
  OpenSSL::Digest::MD4.new(string).hexdigest
end

#Gnerate a MS5 Hash given string
def md5(string)
  OpenSSL::Digest::MD5.new(string).hexdigest
end

# Generate Bcrypt Hash
def bcrypt(string)
  BCrypt::Password.create(string).to_s
end

# Generate Unix style DES crypt() Hash
def des_crypt(string)
  if string.length < 2
    return "Too Short for DES Salt".light_red + '!'.white + "\nString or Username must be 2 char minimum".light_red + '....'.white
  else
    return string.crypt(string)
  end
end

# Generate New Joomla! Hash
def joomla_hash(string)
  # Generate Salt, Create Salty Pass, then Join
  salt = (0..32).map{ rand(36).to_s(36) }.join
  saltypass = Digest::MD5.hexdigest(string + salt)
  j = "#{saltypass}:#{salt}"
  # Return valid Joomla! Hash
  return j
end

# Generate a MySQL SHA1 Hash
def mysql5_hash(string)
  "*" + Digest::SHA1.hexdigest(Digest::SHA1.digest(string)).upcase
end

# Generate Windows LM Hash
def lm(string)
  Smbhash.lm_hash(string)
end

# Generate Windows NTLM Hash
def ntlm(string)
  Smbhash.ntlm_hash(string)
end

# Generate Full Windows LM:NTLM Hash
def ntlm_gen(string)
  Smbhash.ntlmgen(string).join(":")
end

# Generate a SHA1 Hash
def sha1(string)
  OpenSSL::Digest::SHA1.hexdigest(string)
end

# Generate a SHA256 Hash
def sha256(string)
  OpenSSL::Digest::SHA256.hexdigest(string)
end

# Generate a SHA256 Hash
def sha512(string)
  OpenSSL::Digest::SHA512.hexdigest(string)
end




# We need to re-open the String class to extend it a bit
# This will allow us to call some cool functions on strings
class String
  # XOR String, 'data'.xor(genkey)
  def xor(key)
    self.bytes.zip(key.bytes).map { |(a,b)| (a||0) ^ (b||0) }.pack('c*')
  end

  # Convert to Decimal
  def to_decimal
    self.scan(/./).map {|c| c.to_s.ord.to_s(10) }.join(' ')
  end

  # Convert to Octal
  def to_octal
    self.scan(/./).map {|c| c.to_s.ord.to_s(8) }.join(' ')
  end

  # Convert to Binary
  def to_binary
    self.scan(/./).map {|c| c.to_s.ord.to_s(2) }.join(' ')
  end

  # Convert to HEX
  def to_hex
    '\x' + self.scan(/./).map {|c| c.to_s.ord.to_s(16) }.join('\x')
  end

  # Generate MD4 Hash string
  def md4
    OpenSSL::Digest::MD4.new(self).hexdigest
  end

  # MD5 function built into String class :p
  def md5
    OpenSSL::Digest::MD5.new(self).hexdigest
  end

  # Generate Bcrypt Hash
  def bcrypt
    BCrypt::Password.create(self).to_s
  end

  # Generate Unix style DES crypt() Hash
  def des_crypt
    if self.length < 2
      return "Too Short for DES Salt".light_red + '!'.white + "\nString or Username must be 2 char minimum".light_red + '....'.white
    else
      return self.crypt(self)
    end
  end

  # Generate New Joomla! Hash
  def joomla_hash
    salt = (0..32).map{ rand(36).to_s(36) }.join
    saltypass = Digest::MD5.hexdigest(self + salt)
    j = "#{saltypass}:#{salt}"
    return j
  end

  # Generate a SHA1 Hash
  def sha1
    OpenSSL::Digest::SHA1.hexdigest(self)
  end

  # Generate a SHA256 Hash
  def sha256
    OpenSSL::Digest::SHA256.hexdigest(self)
  end

  # Generate a SHA256 Hash
  def sha512
    OpenSSL::Digest::SHA512.hexdigest(self)
  end

  # Generate a MySQL SHA1 Hash
  def mysql5_hash
    "*" + Digest::SHA1.hexdigest(Digest::SHA1.digest(self)).upcase
  end

  # Generate Windows LM Hash
  def lm
    Smbhash.lm_hash(self)
  end

  # Generate Windows NTLM Hash
  def ntlm
    Smbhash.ntlm_hash(self)
  end

  # Generate Full Windows LM:NTLM Hash
  def ntlm_gen
    Smbhash.ntlmgen(self).join(":")
  end

  # Base64 Encode String
  def b64e
    [self].pack("m")
  end

  # Base64 Decode String
  def b64d
    unpack("m")[0]
  end

  # Convert String to HEX Value
  def hexme
    self.each_byte.map { |b| b.to_s(16) }.join
  end

  # Convert String from HEX Value to Char Value
  def dehexme
    self.scan(/../).map { |x| x.hex.chr }.join
  end

  # Simple rot13 Cipher using tr (rot13 is its own reverse, since shift is half the aplhabet, so no reverse function)
  def rot13
    self.tr("A-Za-z", "N-ZA-Mn-za-m")
  end

  # Convert Passed String into its equivelant in ascii code values; "hello".asciime => "104,101,108,108,111"
  def asciime
    foo=[]
    self.each_byte { |byte| foo << byte }
    foo.join(',')
  end

  # HTML Entity Decimal Encoding (&#DD)
  def ent_dec
    foo=[]
    self.scan(/./) { |char| foo << "&\##{char.ord}" }
    return foo.join
  end

  # HTML Entity Decimal Decoding (&#DD)
  def ent_ddec
    foo=[]
    self.scan(/&#\d+/) { |char| if char =~ /&#(\d+)/; foo << $1; end }
    newstr=String.new
    foo.each { |char| newstr += char.to_i.chr }
    return newstr
  end

  # HTML Entity Hex Encoding (&#xXX)
  def ent_hex
    foo=[]
    self.each_byte { |b| foo << "&\#x#{b.to_s(16)}" }
    return foo.join
  end

  # HTML Entity Hex Decoding (&#XX) => It's not perfect but best i could come up with for now :/
  def ent_dhex
    foo=[]
    self.scan(/&#x\d+/) { |char| char.sub!('&#x', ''); foo << char }
    newstr=String.new
    foo.each { |char| newstr += char.hex.chr }
    return newstr
  end

  # HTML Entity Named Encoding (&quot;&gt;&lt;)
  def ent_name
    newstr=CGI.escapeHTML(self)
    return newstr
  end

  # HTML Entity Named Decoding (&quot;&gt;&lt;)
  def ent_dname
    newstr=CGI.unescapeHTML(self)
    return newstr
  end

  # URI Encode String
  def urienc encoding=nil
    begin
      CGI::escape self
    rescue ArgumentError => e
      if e.to_s == 'invalid byte sequence in UTF-8'
        encoding = 'binary' if encoding.nil?
        CGI::escape self.force_encoding(encoding)
      else
        raise e
      end
    end
  end

  # URI Decode String
  def uridec
    CGI::unescape self
  end

  # Double URL Encode string
  def doubleurl
    self.urienc.urienc
  end

  # Convert to unicode url type string
  # Snippet modified from original posted on PacketStorm: http://packetstormsecurity.com/files/69896/unicode-fun.txt.html
  def unicode
    lookuptable = Hash.new
    lookuptable ={
	' ' => '%u0020',
	'/' => '%u2215',
	'\\' => '%u2215',
	"'" => '%u02b9',
	'"' => '%u0022',
	'>' => '%u003e',
	'<' => '%u003c',
	'#' => '%uff03',
	'!' => '%uff01',
	'$' => '%uff04',
	'*' => '%uff0a',
	'@' => '%u0040',
	'.' => '%uff0e',
	'_' => '%uff3f',
	'(' => '%uff08',
	')' => '%uff09',
	',' => '%uff0c',
	'%' => '%u0025',
	'-' => '%uff0d',
	';' => '%uff1b',
	':' => '%uff1a',
	'|' => '%uff5c',
	'&' => '%uff06',
	'+' => '%uff0b',
	'=' => '%uff1d',
	'a' => '%uff41',
	'A' => '%uff21',
	'b' => '%uff42',
	'B' => '%uff22',
	'c' => '%uff43',
	'C' => '%uff23',
	'd' => '%uff44',
	'D' => '%uff24',
	'e' => '%uff45',
	'E' => '%uff25',
	'f' => '%uff46',
	'F' => '%uff26',
	'g' => '%uff47',
	'G' => '%uff27',
	'h' => '%uff48',
	'H' => '%uff28',
	'i' => '%uff49',
	'I' => '%uff29',
	'j' => '%uff4a',
	'J' => '%uff2a',
	'k' => '%uff4b',
	'K' => '%uff2b',
	'l' => '%uff4c',
	'L' => '%uff2c',
	'm' => '%uff4d',
	'M' => '%uff2d',
	'n' => '%uff4e',
	'N' => '%uff2e',
	'o' => '%uff4f',
	'O' => '%uff2f',
	'p' => '%uff50',
	'P' => '%uff30',
	'q' => '%uff51',
	'Q' => '%uff31',
	'r' => '%uff52',
	'R' => '%uff32',
	's' => '%uff53',
	'S' => '%uff33',
	't' => '%uff54',
	'T' => '%uff34',
	'u' => '%uff55',
	'U' => '%uff35',
	'v' => '%uff56',
	'V' => '%uff36',
	'w' => '%uff57',
	'W' => '%uff37',
	'x' => '%uff58',
	'X' => '%uff38',
	'y' => '%uff59',
	'Y' => '%uff39',
	'z' => '%uff5a',
	'Z' => '%uff3a',
	'0' => '%uff10',
	'1' => '%uff11',
	'2' => '%uff12',
	'3' => '%uff13',
	'4' => '%uff14',
	'5' => '%uff15',
	'6' => '%uff16',
	'7' => '%uff17',
	'8' => '%uff18',
	'9' => '%uff19'	}

    # Convert string to array of chars and convert by char as needed
    chararray = self.scan(/./)
    newstr = String.new
    chararray.each do |c|
      if lookuptable.has_key?(c)
        newstr = newstr + lookuptable[c]
      else
        newstr = newstr + CGI::unescape(c)
      end
    end

    return newstr #Return our new unicode string
  end

  # Perform simple random capitlization on string for simple WAF bypass attempts
  def wafcap
    while(true)
      foo=self.split('')
      bar=[]
      foo.each do |char|
        foobar=rand(2)
        if foobar.to_i == 0
          bar << char.upcase
        else
          bar << char.downcase
        end
      end
      check = bar.join
      if not check == self.upcase and not check == self.downcase
        return check
        break
      end
    end
  end

  # Randomly swap letters for integers throughout string
  def randnum
    while(true)
      foo=self.split('')
      bar=[]
      foo.each do |char|
        foobar=rand(2)
        if foobar.to_i == 0
          bar << rand(9)
        else
          bar << char
        end
      end
      return bar.join
    end
  end

  # Randomly swap char for special character char throughout string
  def randspecial
    special = [ '?', '/', '!', '@', '$', '#', '%', '^', '&', '*', '_' ]
    while(true)
      foo=self.split('')
      bar=[]
      foo.each do |char|
        foobar=rand(2)
        if foobar.to_i == 0
          bar << special.shuffle[rand(9)].to_s
        else
          bar << char
        end
      end
      return bar.join
    end
  end
end


# Just checks body of response against regex categories
# simply prints category if match found
# Need to pass the url & response body
# If site=true, logging made in host folder
# If site=false, logs to results/vuln/
def quick_regex_check(link, body, site=false)
  begin
    uri = URI.parse(link)
    target=uri.host
  rescue #Funky Subdomains or bad URL throw errors on parsing, idk...
    target=link.sub('http://','').sub('https://','').split('/')[0]
  end
  vuln=false
  if site
    vdir = RESULTS + target + '/vulns/'
  else
    vdir = RESULTS + '/vulns/'
  end
  Dir.mkdir(vdir) unless File.exists?(vdir) and File.directory?(vdir)

  # ColdFusion
  if body =~ /Invalid CFML construct found|CFM compiler|ColdFusion documentation|Context validation error for tag cfif|ERROR.queryString|Error Executing Database Query|SQLServer JDBC Driver|coldFusion.sql.Parameter|JDBC SQL|JDBC error|SequeLink JDBC Driver|Invalid data .+ for CFSQLTYPE CF_SQL_INTEGER/i
    print_good("ColdFusion: #{link}")
    f=File.open(vdir + 'coldfusion.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # Misc Errors, manually follow up suggested
  if body =~ /Microsoft VBScript runtime|Microsoft VBScript compilation|Invision Power Board Database Error|DB2 ODBC|DB2 error|DB2 Driver|unexpected end of SQL command|invalid query|SQL command not properly ended|An illegal character has been found in the statement|Active Server Pages error|ASP.NET_SessionId|ASP.NET is configured to show verbose error messages|A syntax error has occurred|Unclosed quotation mark|Input string was not in a correct format|<b>Warning<\/b>: array_merge|Warning: array_merge|Warning: preg_match|<b>Warning<\/b>: preg_match|<exception-type>java.lang.Throwable|MODx Parse Error|MODx encountered the following error while attempting to parse the requested resource|Execution of a query to the database failed/i
    print_caution("Misc: #{link}")
    f=File.open(vdir + 'misc.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # MS-Access
  if body =~ /Microsoft JET Database Engine|ADODB.Command|ADODB.Field error|Microsoft Access Driver|ODBC Microsoft Access|BOF or EOF/i
    print_good("MS-Access: #{link}")
    f=File.open(vdir + 'msaccess.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # MS-SQL||Sybase Type Server
  if body =~ /Microsoft OLE DB Provider for SQL Server error|OLE\/DB provider returned message|ODBC SQL Server|ODBC Error|Microsoft SQL Native Client/i
    print_good("MS-SQL: #{link}")
    f=File.open(vdir + 'mssql.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # MySQL
  if body =~ /<b>Warning<\/b>: mysql_query|Warning: mysql_query|<b>Warning<\/b>: mysql_fetch_row|Warning: mysql_fetch_row|<b>Warning<\/b>: mysql_fetch_array|Warning: mysql_fetch_array|<b>Warning<\/b>: mysql_fetch_assoc|Warning: mysql_fetch_assoc|<b>Warning<\/b>: mysql_fetch_object|Warning: mysql_fetch_object|<b>Warning<\/b>: mysql_numrows|Warning: mysql_numrows|<b>Warning<\/b>: mysql_num_rows|Warning: mysql_num_rows|MySQL Error|MySQL ODBC|MySQL Driver|supplied argument is not a valid MySQL result resource|error in your SQL syntax|on MySQL result index|JDBC MySQL|<b>Warning<\/b>: mysql_result|Warning: mysql_result/i
    print_good("MySQL: #{link}")
    f=File.open(vdir + 'mysql.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # Oracle
  if body =~ /Oracle ODBC|Oracle Error|Oracle Driver|Oracle DB2|ODBC DB2|ODBC Oracle|JDBC Oracle|ORA-01756|ORA-00936|ORA-00921|ORA-01400|ORA-01858|ORA-06502|ORA-00921|ORA-01427|ORA-00942|<b>Warning<\/b>: ociexecute|Warning: ociexecute|<b>Warning<\/b>: ocifetchstatement|Warning: ocifetchstatement|<b>Warning<\/b>:  ocifetchinto|Warning: ocifetchinto|error ORA-/i
    print_good("Oracle: #{link}")
    f=File.open(vdir + 'oracle.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # Postgres
  if body =~ /<b>Warning<\/b>: pg_connect|Warning: pg_connect|<b>Warning<\/b>:  simplexml_load_file|Warning:  simplexml_load_file|Supplied argument is not a valid PostgreSQL result|PostgreSQL query failed: ERROR: parser: parse error|<b>Warning<\/b>: pg_exec|Warning: pg_exec/i
    print_good("PostgreSQL: #{link}")
    f=File.open(vdir + 'postgres.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # Confirmed Local File Include
  # Matches /etc/passwd or C:\boot.ini
  if body =~ /(\w+:.:\d+:\d+:.+:.+:\/\w+\/\w+)/m or body =~ /\[boot loader\]|\[operating systems\]/i
    puts "Confirmed LFI".light_green + ": #{link}".white
    f=File.open(vdir + 'confirmed_lfi.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # File Include
  if body =~ /<b>Warning<\/b>:  include|Warning: include|<b>Warning<\/b>: require_once|Warning: require_once|Disallowed Parent Path|<b>Warning<\/b>: main|Warning: main|<b>Warning<\/b>: session_start|Warning: session_start|<b>Warning<\/b>: getimagesize|Warning: getimagesize|<b>Warning<\/b>: include_once|Warning: include_once/i
    print_good("Possible File Include: #{link}")
    f=File.open(vdir + 'file_include.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # Eval()
  if body =~ /eval\(\)'d code<\/b> on line|eval\(\)'d code on line|<b>Warning<\/b>:  Division by zero|Warning:  Division by zero|<b>Parse error<\/b>: syntax error, unexpected|Parse error: syntax error, unexpected|<b>Parse error<\/b>: parse error in|Parse error: parse error in|Notice: Undefined variable: node in eval|<b>Notice<\/b>: Undefined variable: node in eval/i
    print_good("Possible Eval(): #{link}")
    f=File.open(vdir + 'eval.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # Various XML reader/parser functions can be injected into and will generate errors like SQLi
  if body =~ /Warning: XMLReader::open()|<b>Warning<\/b>: XMLReader::open()/i
    print_good("Possible XML Injection or XML Formatting Error: #{link}")
    f=File.open(vdir + 'xml_issues.links', 'a+')
    f.puts link
    f.close
    vuln=true
  end

  # phpinfo() file & information disclosure
  if body =~ /<tr><td class="e">Apache Version <\/td><td class="v">.+<\/td><\/tr>|<h1 class="p">PHP Version .+<\/h1>|<tr><td class="e">System <\/td><td class="v">.+<\/td><\/tr>|<tr><td class="e">DOCUMENT_ROOT <\/td><td class="v">.+<\/td><\/tr>|<tr><td class="e">allow_url_fopen<\/td><td class="v">.+<\/td><td class="v">.+<\/td><\/tr>|<tr><td class="e">magic_quotes_gpc<\/td><td class="v">.+<\/td><td class="v">.+<\/td><\/tr>|<tr><td class="e">safe_mode<\/td><td class="v">.+<\/td><td class="v">.+<\/td><\/tr>|<tr><td class="e">session.save_path<\/td><td class="v">.+<\/td><td class="v">.+<\/td><\/tr>/
    print_good("Possible PHPINFO() File found!")
    f=File.open(vdir + 'phpinfo.links', 'a+')
    f.puts link
    if body =~ /<tr><td class="e">Apache Version <\/td><td class="v">(.+)<\/td><\/tr>/
      puts "\tApache Version".light_green + ": #{$1.chomp}".white
      f.puts "\tApache Version: #{$1.chomp}"
    end
    if body =~ /<h1 class="p">(PHP Version .+)<\/h1>/
      puts "\tPHP Version".light_green + ": #{$1.chomp}".white
      f.puts "\tPHP Version: #{$1.chomp}"
    end
    if body =~ /<tr><td class="e">System <\/td><td class="v">(.+)<\/td><\/tr>/
      puts "\tSystem".light_green + ": #{$1.chomp}".white
      f.puts "\tSystem: #{$1.chomp}"
    end
    if body =~ /<tr><td class="e">DOCUMENT_ROOT <\/td><td class="v">(.+)<\/td><\/tr>/
      puts "\tDocument Root".light_green + ": #{$1.chomp}".white
      f.puts "\tDocument Root: #{$1.chomp}"
    end
    if body =~ /<tr><td class="e">allow_url_fopen<\/td><td class="v">(.+)<\/td><td class="v">.+<\/td><\/tr>/
      puts "\tallow_url_fopen".light_green + ": #{$1.chomp}".white
      f.puts "\tallow_url_fopen: #{$1.chomp}"
    end
    if body =~ /<tr><td class="e">magic_quotes_gpc<\/td><td class="v">(.+)<\/td><td class="v">.+<\/td><\/tr>/
      puts "\tmagic_quotes_gpc".light_green + ": #{$1.chomp}".white
      f.puts "\tmagic_quotes_gpc: #{$1.chomp}"
    end
    if body =~ /<tr><td class="e">safe_mode<\/td><td class="v">(.+)<\/td><td class="v">.+<\/td><\/tr>/
      puts "\tsafe_mode".light_green + ": #{$1.chomp}".white
      f.puts "\tsafe_mode: #{$1.chomp}"
    end
    if body =~ /<tr><td class="e">session.save_path<\/td><td class="v">(.+)<\/td><td class="v">.+<\/td><\/tr>/
      puts "\tsession.save_path".light_green + ": #{$1.chomp}".white
      f.puts "\tsession.save_path: #{$1.chomp}"
    end
    f.puts
    f.close
    vuln=true
  end

  if vuln
    return true
  else
    return false
  end
end

# Find Internal IP Address
def ip_local(verbose=true)
  orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # RevDNS = Off, so dont resolve!
  UDPSocket.open do |sox|
    sox.connect '74.125.227.32', 1 # Google, but we dont actually connect
    sox.addr.last
    print_good("Internal IP: #{sox.addr.last}") if verbose
    return sox.addr.last
  end
  rescue SocketError => e # sox shit happens?
    print_error("Problem Getting Internal IP!") if verbose
    return nil
  ensure
    Socket.do_not_reverse_lookup = orig
end

# Find External IP Address
def external_local(verbose=true)
  begin
    http=EasyCurb.new()
    res = http.get("http://checkip.dyndns.org/")
    ip = res[0].match(/\d+\.\d+\.\d+\.\d+/)
    print_good("External IP: #{IPAddr.new(ip[0])}") if verbose
    return IPAddr.new(ip[0])
  rescue => e
    print_error("Problem Getting External IP!") if verbose
    return nil
  end
end

# Find Internal & External IP
def ip_info
  puts
  ip_local
  external_local
end

