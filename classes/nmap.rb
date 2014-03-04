# Simple NMAP Class for scanning and parsing results files...

class NMAP
  # Just make sure they have NMAP in path
  def initialize
    check = commandz('which nmap')[0]
    if check.nil?
      begin
        raise "NMAP Not Found in PATH".light_red + "!".white + "\nCan't run NMAP options without".light_red + "......\n\n".white
      rescue
        return false
      end
    else
      @@outdir=RESULTS + 'recon/'
      Dir.mkdir(@@outdir) unless File.exists?(@@outdir) and File.directory?(@@outdir)
      return true
    end
  end

  # Setup & Run NMAP Scan
  def scanner(target, nse=true)
    nmap = commandz('which nmap')[0].to_s.chomp
    if Process.uid == 0
      nmap += ' -sS -A -T3 -PN ' # SYN Scan, Version + OS Detection Enabled, Mild Timing, No Ping Check
      if nse
        nmap  += '-sC ' # Enable NSE Scripts
      end
    else # Not root, can't use Syn Scan
      print_error("Not running with root privs!")
      print_error("Limited scans we can run with NMAP as result....")
      nmap += ' -A -T3 -PN ' # SYN Scan, Version + OS Detection Enabled, Mild Timing, No Ping Check
    end
    Dir.mkdir(@@outdir + target.chomp + '/') unless File.exists?(@@outdir + target.chomp + '/') and File.directory?(@@outdir + target.chomp + '/')
    nmap += "#{target.chomp} -oX #{@@outdir}#{target.chomp}/nmap_results.xml"
    print_status("Running NMAP Scan, hang tight for a sec....")
    system("#{nmap}")
    puts
  end

  # Specific Service Scanning
  # Used for Service Scan & Brute Tool
  # Returns location of greppable output file 
  # Use that with grep parser and get hosts list to target...
  def service_scanner(target, service='smb', port=nil)
    nmap = commandz('which nmap')[0].to_s.chomp
    Dir.mkdir(@@outdir + target.chomp.gsub('/', '_') + '/') unless File.exists?(@@outdir + target.chomp.gsub('/', '_') + '/') and File.directory?(@@outdir + target.chomp.gsub('/', '_') + '/')
    if Process.uid != 0
      print_error("Not running with privs, may affect scan results!")
    end
    case service
    when 'mssql'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/mssql-nmap_grepable_output"
      if port.nil?
        system("#{nmap} #{target} -sT -sU -p U:1434,T:1433 -Pn -sV --open -oG #{out}")
      else
        system("#{nmap} #{target} -p #{port} -sV --open -Pn -oG #{out}")
      end
    when 'mysql'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/mysql-nmap_grepable_output"
      if port.nil?
        port = 3306
      end
      system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
    when'pgsql'
      if port.nil?
        port = 5432
      end
      system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
    when 'rdp'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/rdp-nmap_grepable_output"
      if port.nil?
        port = 3389
      end
      system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
    when 'ssh'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/rdp-nmap_grepable_output"
      if port.nil?
        port = '22,2222'
      end
      system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
    when 'ftp'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/rdp-nmap_grepable_output"
      if port.nil?
        port = '21'
      end
      system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
    when 'telnet'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/rdp-nmap_grepable_output"
      if port.nil?
        port = '23'
      end
      system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
    when 'winrm'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/rdp-nmap_grepable_output"
      if port.nil?
        port = 5985
      end
      system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
    when 'smb'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/smb-nmap_grepable_output"
      if port.nil?
        system("#{nmap} #{target} -sT -sU -Pn -sV -p U:137,U:138,T:137,T:139,T:445 -script=smb-os-discovery,smb-security-mode --open -oG #{out}")
      else
        system("#{nmap} #{target} -sT -sU -Pn -sV -p U:137,U:138,T:137,T:139,T:445,#{port} -script=smb-os-discovery,smb-security-mode --open -oG #{out}")
      end
    when 'snmp'
      out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/snmp-nmap_grepable_output"
      if port.nil?
        port = '161,162,10161,10162'
        system("#{nmap} #{target} -sU -p #{port} -Pn -sV -sC --open -oG #{out}")
      else
        system("#{nmap} #{target} -sU -p #{port} -Pn -sV -sC --open -oG #{out}")
      end
    else
      if port.nil?
        out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/nil-nmap_grepable_output"
        system("#{nmap} #{target} -A -T3 -Pn -sV --open -oG #{out}")
      else
        out = "#{@@outdir}#{target.chomp.gsub('/', '_')}/custom-nmap_grepable_output"
        system("#{nmap} #{target} -p #{port} -Pn -sV --open -oG #{out}")
      end
    end
    return out
  end

  # Grab IP Addresses from NMAP Greppable Output
  def grep_output_to_hosts(grep_output_file)
    if File.exists?(grep_output_file)
      ipz=[]
      count=0
      # Grab IP Addresses from the NMAP Output file
      res = File.open(grep_output_file).readlines
      res.each do |line|
        if line =~ /Host: .+ /
          ipz << line.split(' ')[1]
        end
      end
      ip = ipz.uniq
      return ip
    else
      print_error("Unable to load greppable output file!")
      print_error("Check path or permissions and try again....")
      return nil
    end
  end

  # Parse NMAL XML Scan Results
  def nmap_xml_parser(file='./results/recon/127.0.0.1/nmap_results.xml')
    if File.exists?(file)
      # Parser Code Here using SimpleXML, TBD....
      #########################################################
      print_error("NMAP XML Parser Not Fully Implemented Yet!")
      #########################################################
    else
      puts
      print_error("Unable to load #{file} for parsing!")
      print_error("Check path or permissions and try again....\n\n")
    end
  end
end
