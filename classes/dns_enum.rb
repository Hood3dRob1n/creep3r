# DNS Enumeration or Recon Class and functions

# Simple DNS Enumeration Class I wrote
# Leverages Ruby's Builtin Resolv at Core
# Enumerates most of the well known DNS record types
# Also enumerates hosts using Bing Search Engine
class DNSEnum
  def initialize(host)
    puts
    @@host=host
    @@ip, @@domain, @@hostname = host_info(host)
    Dir.mkdir(RESULTS + 'recon/') unless File.exists?(RESULTS + 'recon/') and File.directory?(RESULTS + 'recon/')
    Dir.mkdir(RESULTS + 'recon/' + host) unless File.exists?(RESULTS + 'recon/' + host) and File.directory?(RESULTS + 'recon/' + host)
    @@out = RESULTS + 'recon/' + host + "/host_recon.txt"
    @@file = File.open(@@out, 'w+')

    # All valid Top Level Domains (TLD's) according to ICANN
    # http://www.icann.org/en/resources/registries/tlds
    @valid_tld = [ "AC", "ACADEMY", "AD", "AE", "AERO", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ", "AR", "ARPA", "AS", "ASIA", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BERLIN", "BF", "BG", "BH", "BI", "BIKE", "BIZ", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BUILDERS", "BUZZ", "BV", "BW", "BY", "BZ", "CA", "CAB", "CAMERA", "CAMP", "CAREERS", "CAT", "CC", "CD", "CENTER", "CEO", "CF", "CG", "CH", "CI", "CK", "CL", "CLOTHING", "CM", "CN", "CO", "CODES", "COFFEE", "COM", "COMPANY", "COMPUTER", "CONSTRUCTION", "CONTRACTORS", "COOP", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DIAMONDS", "DIRECTORY", "DJ", "DK", "DM", "DO", "DOMAINS", "DZ", "EC", "EDU", "EDUCATION", "EE", "EG", "EMAIL", "ENTERPRISES", "EQUIPMENT", "ER", "ES", "ESTATE", "ET", "EU", "FARM", "FI", "FJ", "FK", "FLORIST", "FM", "FO", "FR", "GA", "GALLERY", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GLASS", "GM", "GN", "GOV", "GP", "GQ", "GR", "GRAPHICS", "GS", "GT", "GU", "GURU", "GW", "GY", "HK", "HM", "HN", "HOLDINGS", "HOLIDAY", "HOUSE", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IMMOBILIEN", "IN", "INFO", "INSTITUTE", "INT", "INTERNATIONAL", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JOBS", "JP", "KAUFEN", "KE", "KG", "KH", "KI", "KITCHEN", "KIWI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LAND", "LB", "LC", "LI", "LIGHTING", "LIMO", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MANAGEMENT", "MC", "MD", "ME", "MENU", "MG", "MH", "MIL", "MK", "ML", "MM", "MN", "MO", "MOBI", "MP", "MQ", "MR", "MS", "MT", "MU", "MUSEUM", "MV", "MW", "MX", "MY", "MZ", "NA", "NAME", "NC", "NE", "NET", "NF", "NG", "NI", "NINJA", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "ONL", "ORG", "PA", "PE", "PF", "PG", "PH", "PHOTOGRAPHY", "PHOTOS", "PK", "PL", "PLUMBING", "PM", "PN", "POST", "PR", "PRO", "PS", "PT", "PW", "PY", "QA", "RE", "RECIPES", "REPAIR", "RO", "RS", "RU", "RUHR", "RW", "SA", "SB", "SC", "SD", "SE", "SEXY", "SG", "SH", "SHOES", "SI", "SINGLES", "SJ", "SK", "SL", "SM", "SN", "SO", "SOLAR", "SOLUTIONS", "SR", "ST", "SU", "SUPPORT", "SV", "SX", "SY", "SYSTEMS", "SZ", "TATTOO", "TC", "TD", "TECHNOLOGY", "TEL", "TF", "TG", "TH", "TIPS", "TJ", "TK", "TL", "TM", "TN", "TO", "TODAY", "TP", "TR", "TRAINING", "TRAVEL", "TT", "TV", "TW", "TZ", "UA", "UG", "UK", "UNO", "US", "UY", "UZ", "VA", "VC", "VE", "VENTURES", "VG", "VI", "VIAJES", "VN", "VOYAGE", "VU", "WANG", "WF", "WIEN", "WS", "XN--3BST00M", "XN--3DS443G", "XN--3E0B707E", "XN--45BRJ9C", "XN--55QW42G", "XN--6QQ986B3XL", "XN--80AO21A", "XN--80ASEHDB", "XN--80ASWG", "XN--90A3AC", "XN--CLCHC0EA0B2G2A9GCD", "XN--FIQ228C5HS", "XN--FIQS8S", "XN--FIQZ9S", "XN--FPCRJ9C3D", "XN--FZC2C9E2C", "XN--GECRJ9C", "XN--H2BRJ9C", "XN--J1AMH", "XN--J6W193G", "XN--KPRW13D", "XN--KPRY57D", "XN--L1ACC", "XN--LGBBAT1AD8J", "XN--MGB9AWBF", "XN--MGBA3A4F16A", "XN--MGBAAM7A8H", "XN--MGBAYH7GPA", "XN--MGBBH1A71E", "XN--MGBC0A9AZCG", "XN--MGBERP4A5D4AR", "XN--MGBX4CD0AB", "XN--NGBC5AZD", "XN--O3CW4H", "XN--OGBPF8FL", "XN--P1AI", "XN--PGBS0DH", "XN--Q9JYB4C", "XN--S9BRJ9C", "XN--UNUP4Y", "XN--WGBH1C", "XN--WGBL6A", "XN--XKC2AL3HYE2A", "XN--XKC2DL3A5EE0H", "XN--YFRO4I67O", "XN--YGBI2AMMX", "XN--ZFR164B", "XXX", "YE", "YT", "ZA", "ZM", "ZW"]
  end

  # We will perform some basic recon on requested host/ip
  # Basically runs through all of our available functions
  # Resolve Host/Domain to IP and vice versa
  # Enumerate Nameservers and Mail Servers via DNS
  # Enumerate Hosts via Bing Search using ip:#{ip} filter
  # Results are printed in terminal and logged to RESULTS dir
  def host_recon(host=@@host)
    @@file.puts "##########################################"
    @@file.puts "IP: #{@@ip}"
    @@file.puts "Domain: #{@@domain}" unless @@domain == @@ip
    @@file.puts "Hostname: #{@@hostname}"
    @@file.puts "##########################################"
    puts "##########################################".light_blue
    print_good("IP: #{@@ip}")
    print_good("Domain: #{@@domain}") unless @@domain == @@ip
    print_good("Hostname: #{@@hostname}")
    puts "##########################################".light_blue

    # Check if domain maps to more than one IP address
    # This may occur with load balancers or other types of configurationss
    domain_2_ip=[]
    Resolv.each_address(@@domain) do |x|
      if domain_2_ip.size > 0
        @@file.puts "\nAdditional IP's #{@@domain} Maps to: "
        print_good("Additional IP's #{@domain} Maps to: ")
        domain_2_ip.each do |x|
          case x
          when Resolv::IPv4::Regex
            @@file.puts "   IPv4: #{x}" unless x == @@ip
            puts "  [".light_blue + "+".white + "] ".light_blue + "IPv4:   #{x}".white unless x == @ip
          when Resolv::IPv6::Regex
            @@file.puts "   IPv6: #{x}" unless x == @@ip
            puts "  [".light_blue + "+".white + "] ".light_blue + "IPv6:   #{x}".white unless x == @ip
          else
            @@file.puts "     IP: #{x}" unless x == @@ip
            puts "  [".light_blue + "+".white + "] ".light_blue + "IP:   #{x}".white unless x == @ip
          end
        end
      end
    end

    # Check for other Domains Mapped to IP (AXFR?)
    # This occurs in shared hosting situations
    # Also occasionally due to outdated records
    ip_2_domain=[]
    Resolv.getnames(@@ip) do |x|
      if ip_2_domain.size > 0
        @@file.puts "\nDomain's Mapped to #{@@ip} according to DNS: "
        print_good("Domain's Mapped to #{@@ip} according to DNS: ")
        ip_2_domain.each do |x|
          @@file.puts "   #{x}" unless x == @@domain
          puts "    [".light_blue + "+".white + "] ".light_blue + "#{x}".white unless x == @domain
        end
      end
    end

    # Enumeration via Bing Search ip:<ip>
    bing_ip2hosts(@@ip)
    puts

    # DNS Enumeration of any available Records
    dns_soa_records   # SOA Records
    puts
    dns_ns_records    # Nameservers
    puts
    dns_mx_records    # Mailers
    puts
    dns_a_records     # IPv4
    dns_aaaa_records  # IPv6
    dns_srv_records   # Services
    dns_wks_records   # Services
    dns_txt_records   # TXT
    dns_ptr_records   # Other Domains
    puts
    tld_expansion_check # TLD Expansion/Enumeration Check
    @@file.close
    puts "##########################################\n".light_blue
  end

  # Resolve Domain to IP and vice versa
  def host_info(host=@@host)
    url = URI.parse(host)
    if url.scheme == 'http' || url.scheme =='https'
      domain = url.host.sub('www.', '')
    else 
      domain = host
    end
    begin
      ip = Resolv.getaddress(domain) # Resolve Domain to IP to run check
    rescue Resolv::ResolvError => e
      ip = "Unable to Resolve"
    end
    begin
      hostname = Resolv.getname(ip).chomp  # Get hostname for IP
    rescue Resolv::ResolvError => e
      hostname = "Unable to Resolve"
    end
    return ip, domain, hostname
  end

  # Enumerate the SOA Records
  def dns_soa_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      soa_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::SOA)
      if not soa_servers.empty?
        @@file.puts "\nDNS Start of Authority (SOA) Records Found: "
        print_good("DNS Start of Authority (SOA) Records Found: ")
        soa_servers.each do |srvr|
          @@file.puts "   Master: #{srvr.mname}"
          @@file.puts "    Admin: #{srvr.rname}"
          @@file.puts "  Zone File Version: #{srvr.rname}"
          @@file.puts "  Expire:  #{srvr.expire}"
          @@file.puts "  TTL Min: #{srvr.minimum}"
          @@file.puts "  Refresh: #{srvr.refresh}"
          @@file.puts "    Retry: #{srvr.retry}"
          puts "   [".light_blue + "+".white + "] ".light_blue + "Master: #{srvr.mname}".white
          puts "   [".light_blue + "+".white + "] ".light_blue + "Admin: #{srvr.rname}".white
          puts "   [".light_blue + "+".white + "] ".light_blue + "Zone File Version: #{srvr.serial}".white
          puts "      [".light_blue + "-".white + "] ".light_blue + "Expire:  #{srvr.expire}".white
          puts "      [".light_blue + "-".white + "] ".light_blue + "TTL Min: #{srvr.minimum}".white
          puts "      [".light_blue + "-".white + "] ".light_blue + "Refresh: #{srvr.refresh}".white
          puts "      [".light_blue + "-".white + "] ".light_blue + "Retry:   #{srvr.retry}".white
        end
      else
        puts "[".light_red + "*".white + "] ".light_red + "No DNS SOA Records Found!".white
      end
    end
  end

  # Enumerate IPv4 Address (A) Records
  def dns_a_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      a_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::A)
      if not a_servers.empty?
        @@file.puts "\nDNS IPv4 Address (A) Records Found: "
        print_good("DNS IPv4 Address (A) Records Found: ")
        a_servers.each do |srvr|
          @@file.puts "  #{srvr.address}"
          puts "    [".light_blue + "+".white + "] ".light_blue + "#{srvr.address}".white
        end
      else
        print_error("No DNS A Records Found!")
      end
    end
  end

  # Enumerate IPv6 Address (AAAA) Records
  def dns_aaaa_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      aaaa_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::AAAA)
      if not aaaa_servers.empty?
        @@file.puts "\nDNS IPv6 Address (AAAA) Records Found: "
        puts "[".light_green + "*".white + "] ".light_green + "DNS IPv6 Address (AAAA) Records Found: ".white
        aaaa_servers.each do |srvr|
          @@file.puts "   #{srvr.address}"
          puts "    [".light_blue + "+".white + "] ".light_blue + "#{srvr.address}".white
        end
      else
        print_error("No DNS AAAA Records Found!")
      end
    end
  end

  # Enumerate SRV Records
  def dns_srv_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      srv_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::SRV)
      if not srv_servers.empty?
        @@file.puts "\nDNS SRV Records Found: "
        puts "[".light_green + "*".white + "] ".light_green + "DNS SRV Records Found: ".white
        srv_servers.each do |srvr|
          @@file.puts "   Domain: #{srvr.target},  Port: #{srvr.port}"
          @@file.puts "     Priority: #{srvr.priority}, Weight: #{srvr.weight}"
          puts "   [".light_blue + "+".white + "] ".light_blue + " Domain: #{srvr.target},  Port: #{srvr.port}".white
          puts "       [".light_blue + "-".white + "] ".light_blue + "Priority: #{srvr.priority}, Weight: #{srvr.weight}".white
        end
      else
        print_error("No DNS SRV Records Found!")
      end
    end
  end

  # Enumerate Well Known Services (WKS) Records
  def dns_wks_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      wks_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::WKS)
      if not wks_servers.empty?
        @@file.puts "\nDNS Well Known Services (WKS) Records Found: "
        puts "[".light_green + "*".white + "] ".light_green + "DNS Well Known Services (WKS) Records Found: ".white
        wks_servers.each do |srvr|
          @@file.puts "#{srvr.address} | #{srvr.protocol} | #{srvr.bitmap}"
          puts "    [".light_blue + "+".white + "] ".light_blue + "#{srvr.address} | #{srvr.protocol} | #{srvr.bitmap}".white
        end
      else
        print_error("No DNS WKS Records Found!")
      end
    end
  end

  # Enumerate Nameserver (NS) Records
  def dns_ns_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      ns_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::NS)
      if not ns_servers.nil? and ns_servers.size > 0
        @@file.puts "\nDNS Nameserver (NS) Records Found: "
        puts "[".light_green + "*".white + "] ".light_green + "DNS Nameserver (NS) Records Found: ".white
        ns_servers.each do |srvr|
          @@file.puts "   #{srvr.name}"
          puts "    [".light_blue + "+".white + "] ".light_blue + "#{srvr.name}".white
          dns_axfr(@@domain, srvr.name) # Zone Transfer Attempt
        end
      else
        print_error("No DNS NS Records Found!")
      end
    end
  end

  # Simple Zone Transfer Wrapper
  # Couldn't get Resolv to do it...
  # So I am using DIG to do it, take i to r leave it :p
  def dns_axfr(target=@@domain, nssrv='ns1.google.com')
    dig = commandz("which dig")
    if dig.nil?
      puts "       [".light_red + "X".white + "] ".light_red + "No Zone Transfers w/out Dig!".white
    else
      res = commandz("#{dig[0].to_s.chomp} @#{nssrv} #{target} axfr 2> /dev/null")
      if res[-1] =~ /Transfer failed/i
        puts "       [".light_red + "-".white + "] ".light_red + "Zone Transfer Failed!".white
      else
        puts "       [".light_red + "-".white + "] ".light_red + "Successfull Zone Transfer!".white
        puts res.join().to_s.white
        @@file.puts "\nSuccessfull Zone Transfer!"
        @@file.puts res.join().to_s
      end
    end
  end

  # Enumerate MX Records
  def dns_mx_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      mail_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::MX)
      if not mail_servers.empty?
        @@file.puts "\nDNS Mail (MX) Records Found: "
        puts "[".light_green + "*".white + "] ".light_green + "DNS Mail (MX) Records Found: ".white
        mail_servers.each do |mailsrv|
          @@file.puts "   #{mailsrv.exchange.to_s} - #{mailsrv.preference}"
          puts "    [".light_blue + "+".white + "] ".light_blue + "#{mailsrv.exchange.to_s} - #{mailsrv.preference}".white
        end
      else
        print_error("No Mail (MX) Records Found!")
      end
    end
  end

  # Enumerate Pointer (PTR) Records
  def dns_ptr_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      ptr_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::PTR)
      if not ptr_servers.empty?
        @@file.puts "\nDNS Pointer (PTR) Records Found: "
        puts "[".light_green + "*".white + "] ".light_green + "DNS Pointer (PTR) Records Found: ".white
        ptr_servers.each do |srvr|
          @@file.puts "  #{srvr}"
          puts "    [".light_blue + "+".white + "] ".light_blue + "#{srvr}".white
        end
      else
        print_error("No DNS PTR Records Found!")
      end
    end
  end

  # Enumerate Unstructured Text (TXT) Records
  def dns_txt_records(domain=@@domain)
    Resolv::DNS.open do |dns|
      txt_servers = dns.getresources(domain, Resolv::DNS::Resource::IN::TXT)
      if not txt_servers.empty?
        @@file.puts "\nDNS TXT Records Found: "
        puts "[".light_green + "*".white + "] ".light_green + "DNS TXT Records Found: ".white
        txt_servers.each do |srvr|
          if srvr.strings.size > 1
            srvr.strings.each {|x| puts "    [".light_blue + "+".white + "] ".light_blue + "#{x}".white; @@file.puts "#{x}" }
          else
            @@file.puts "   #{srvr.data}"
            puts "    [".light_blue + "+".white + "] ".light_blue + "#{srvr.data}".white
          end
        end
      else
        print_error("No DNS TXT Records Found!")
      end
    end
  end

  # Enumerate Hosts using Bing and the "ip:#{ip}" filter
  # checked or validated via DNS revolving of domains found
  # Returns array of domains on IP or nil
  def bing_ip2hosts(ip=@@ip)
    hosts=[]
    squery = "ip%3A#{ip}"
    bing = SearchEngine.new
    blinks = bing.bing_search(squery, false)
    blinks.uniq.each do |link|
      url = URI.parse(link)
      hosts << url.host unless hosts.include?(url.host)
    end
    if hosts.size > 0
      @@file.puts "\nDomains Found on #{ip} via Bing: "
      print_good("Domains Found on #{ip} via Bing: ")
      hosts.each do |h|
        begin
          zip = Resolv.getaddress(h) # Resolve Domain to IP to run check
        rescue Resolv::ResolvError => e
          zip = "??.??.??.??"
        end
        @@file.puts "   #{h} (#{ip})"
        if zip == ip
          puts "   [".light_green + "+".white + "] ".light_green + "#{h}".white # Host on Same Server for sure
          puts "      [".light_green + "+".white + "] ".light_green + " Resolves to: #{zip}".white
        else
          puts "   [".light_red + "+".white + "] ".light_red + "#{h}".white # Host might be on Server, not sure
          puts "      [".light_red + "-".white + "] ".light_red + " Resolves to: #{zip}".white
        end
      end
      return hosts
    else
      print_error("No Domains Found on #{ip} via Bing Search!")
      return nil
    end
  end

  # Run TLD Enumeration if we have Domain
  def tld_expansion_check(domain=@@domain)
    dom = domain.split('.')[0]
    @@file.puts "\nTLD Expansion Search: "
    print_good("TLD Expansion Search: ")
    @valid_tld.each do |tld|
      expanded = dom + '.' + tld.downcase
      begin
        zip = Resolv.getaddress(expanded) # Resolve Domain to IP to run check
        @@file.puts "#{expanded} => #{zip}"
        if zip == @@ip
          puts "   [".light_green + "+".white + "] ".light_green + "#{expanded}".white # Host on Same Server for sure
          puts "      [".light_green + "+".white + "] ".light_green + " Resolves to: #{zip}".white
        else
          puts "   [".light_blue + "+".white + "] ".light_blue + "#{expanded}".white # Host might be on Server, not sure
          puts "      [".light_blue + "-".white + "] ".light_blue + " Resolves to: #{zip}".white
        end
      rescue Resolv::ResolvError => e
        # Do Nothing, just keep moving....
      end
    end
  end

  # Threaded Sub-Domain Bruteforcer
  # Pic: http://i.imgur.com/oNXhVah.png
  # Pass in wordlist and it will attempt to resolve each possibility
  # Returns an array subdomains found or nil
  def subdomain_bruter(list="#{HOME}fuzz/subs_all.txt", domain=@@domain)
    if File.exists?(list)
      count = File.foreach(list).inject(0) {|c, line| c+1}
      Dir.mkdir(RESULTS + 'recon/' + @@host) unless File.exists?(RESULTS + 'recon/' + @@host) and File.directory?(RESULTS + 'recon/' + @@host)
      out = RESULTS + 'recon/' + @@host + "/sub_domains.txt"
      possibles = File.open(list).readlines

      puts "##########################################".light_blue
      puts "#".light_blue + "     Creep3r Sub-Domain Bruteforcer     ".white + "#".light_blue
      puts "##########################################".light_blue
      print_status("Domain: #{domain}")
      print_status("Fuzzies: #{count}")
      print_status("Fuzz File: #{list.sub(HOME, './')}")
      puts "##########################################".light_blue

      @subs={}                                           # Results stored in Hash array
      counter=0                                          # Tracker
      max_threads = 16                                   # Max Threads
      cur_threads = []                                   # Thread Pool Storage
      queue = possibles.uniq.shuffle                     # Total fuzzies is our total queue
      while(queue.length > 0)                            # Loop while fuzzies left to test
        while(cur_threads.length < max_threads)          # Dont exceed thread pool
          counter += 1                                   # Increment our tracker
          item = queue.shift                             # Pop one off stack each iteration
          break if not item                              # Bounce if we are out of subs to try
          next if item.strip.chomp == '' or item =~ /^#/ # Skip Blanks/Comments
          print "\r(".light_red + "#{counter}".white + "/".light_yellow + "#{count}".white + ")> ".light_red + "#{(100 * (counter.to_f / count.to_f)).to_i}%".white                               # Status display
          t = Thread.new(item) do |count|                # Break off worker thread
            s = item.strip.chomp + ".#{domain.downcase}" # Build our sub.domain
            begin
              i = Resolv.getaddress(s)                   # Try to resolve sub.domain to IP as our simple check      
              @subs.store(s, i)                          # Store Findings in hash, @subs[sub.domain] = 'IP'
            rescue Resolv::ResolvError => e              
              next                                       # Skip Errors, continue forward
            end
          end
          cur_threads << t                               # Collect our threads
        end

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

      # Clean up any remaining threads
      cur_threads.each {|x| x.kill }

      # Report findings if any
      if not @subs.nil? and @subs.size > 0
        puts
        print_status("Found #{@subs.size} sub-domains: ")
        puts '   ' + @subs.keys.join("\n   ").to_s.white
        file = File.open(out, 'w+')
        file.puts "##########################################"
        file.puts "#     Creep3r Sub-Domain Bruteforcer     #"
        file.puts "##########################################"
        file.puts "# Domain: #{domain}"
        file.puts "# Fuzzies: #{count}"
        file.puts "# Fuzz File: #{list.sub(HOME, './')}"
        file.puts "# Sub-Domains Found: #{@subs.size}"
        file.puts "##########################################"
        @subs.each do |k, v|
          file.puts "#{k}"
          file.puts "   => #{v}"
        end
        file.close
      else
        print_error("No Sub-Domains Identified")
      end
      return @subs # Return findings
    else
      puts
      print_error("Unable to load sub-domain wordlist!")
      print_error("Check path or permissions and try again...\n")
    end
    return nil
  end
end
