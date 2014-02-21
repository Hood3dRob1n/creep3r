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
    Dir.mkdir(@@outdir + target + '/') unless File.exists?(@@outdir + target + '/') and File.directory?(@@outdir + target + '/')
    nmap += "#{target.chomp} -oX #{@@outdir}#{target}/nmap_results.xml"
    print_status("Running NMAP Scan, hang tight for a sec....")
    system("#{nmap}")
    puts
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
