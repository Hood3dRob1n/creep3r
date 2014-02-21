# Tamper SQL Class
# WAF Bypassing and other common adjustments can be made through passing injection strings through functions in this class
# Leverages functions from support and sqli_helpers but runs them in a logical manner

# Configure, then Pass in string, it gets tampered, add delimiter when done and place injection string where needed, then send request....
class TamperSQL
  def initialize
    # If you add more options, then add them here too!
    @opts = [ 'wafcap', 'wafcap_common', 'keywords_doubleup', 'comment_keywords', 'mysql_comment_keywords', 'mysql_zero_version_comment_keywords', 'mysql_random_keywords_comment', 'hex_encode_keywords', 'mysql_modsec_versioned_comment', 'mysql_modsec_zero_version_comment', 'securesphere', 'bluecoat', 'equal2like', 'gt2between', 'percent', 'singleq2utf', 'singleq2null', 'unmagicquotes', 'addnull, adddash', 'addsdash', 'addhash', 'addcomm', 'addsp', 'space2comment', 'space2mycomment', 'space2dash', 'space2dashline', 'space2hash', 'space2hashline', 'space2mssql', 'space2mysql', 'space2rand', 'space2oa', 'space2o9', 'space2ob', 'space2oc', 'space2od', 'space2plus', 'floor2xor', 'floor2greatest', 'floor2div', 'floor2round', 'floor2rand', 'comma2comm', 'comma2mycomm', 'comma2char' ]
    @tampersql=false
  end

  # UI Configuration
  def config
    # Ask if user knows what they want of if they need to go through wizard
    while(true)
      print_caution("Select Tamper Setup: ")
      print_caution("0) No Tamper")
      print_caution("1) Display & Set")
      print_caution("2) I know what I want")
      answer=gets.chomp
      puts
      if answer.to_i >= 0 and answer.to_i <= 2
        if answer.to_i == 0
          print_status("OK, disabling tamper options....")
          @tampersql=false
          break
        elsif answer.to_i == 1
          # Wizard_Setup if needed to build up all needed aspects
          wizard_setup
          break
        else
          # Batch_Setup if they know, just ask for comma separated list of options
          print_caution("Please provide comma seperated list of options to enable: ")
          answer=gets.chomp
          badeggs=[]
          options=[]
          @tampersql=true
          optz=answer.split(",")
          optz.each do |o|
            if @opts.include?(o)
              options << o
            else
              badeggs << o
            end
          end
          print_line("")
          if badeggs.size > 0
            print_status("Discarded #{badeggs.size} options as they did not appear to be valid!")
            badeggs.each {|x| print_error("#{x} - discarded!") }
          end
          @tamper = options
          break
        end
      else
        print_line("")
        print_error("Please select valid option from below!")
        print_line("")
      end
    end
  end

  # Wizard Driven Setup of Tamper Options
  # Follow menus to setup...
  def wizard_setup
    @tampersql=true
    print_status("Listing the available Options for tamper menu........")
    @opts.each { |o| print_caution(o) }
    print_line("")
    print_caution("Provide a comma separated list of options to enable: ")
    answer=gets.chomp
    badeggs=[]
    options=[]
    optz=answer.split(",")
    optz.each do |o|
      if @opts.include?(o)
        options << o
      else
        badeggs << o
      end
    end
    print_line("")
    if badeggs.size > 0
      print_status("Discarded #{badeggs.size} options as they did not appear to be valid!")
      badeggs.each {|x| print_error("#{x} - discarded!") }
      print_line("")
    end
    @tamper = options
  end

  # Do the tampering when called from injector classes or wheerever...
  def tamper(string)
    if @tampersql
      @string_tampererd = string
      @tamper.each do |tamperopt|
        case tamperopt
        when 'wafcap'
          @string_tampererd = @string_tampererd.wafcap
        when 'wafcap_common'
          @string_tampererd = @string_tampererd.wafcap_common
        when 'keywords_doubleup'
          @string_tampererd = @string_tampererd.keywords_doubleup
        when 'comment_keywords'
          @string_tampererd = @string_tampererd.comment_keywords
        when 'mysql_comment_keywords'
          @string_tampererd = @string_tampererd.mysql_comment_keywords
        when 'mysql_zero_version_comment_keywords'
          @string_tampererd = @string_tampererd.mysql_zero_version_comment_keywords
        when 'mysql_random_keywords_comment'
          @string_tampererd = @string_tampererd.mysql_random_keywords_comment
        when 'hex_encode_keywords'
          @string_tampererd = @string_tampererd.hex_encode_keywords
        when 'mysql_modsec_versioned_comment'
          @string_tampererd = @string_tampererd.mysql_modsec_versioned_comment
        when 'mysql_modsec_zero_version_comment'
          @string_tampererd = @string_tampererd.mysql_modsec_zero_version_comment
        when 'securesphere'
          @string_tampererd = @string_tampererd.securesphere
        when 'bluecoat'
          @string_tampererd = @string_tampererd.bluecoat
        when 'equal2like'
          @string_tampererd = @string_tampererd.equal2like
        when 'gt2between'
          @string_tampererd = @string_tampererd.gt2between
        when 'percent'
          @string_tampererd = @string_tampererd.percent
        when 'singleq2utf'
          @string_tampererd = @string_tampererd.singleq2utf
        when 'singleq2null'
          @string_tampererd = @string_tampererd.singleq2null
        when 'unmagicquotes'
          @string_tampererd = @string_tampererd.unmagicquotes
        end
      end
      return @string_tampererd
    else
      return string
    end
  end

  # Do the tampering when called from injector classes or wheerever...
  def floor(string)
    if @tampersql
      @string_tampererd = string
      @tamper.each do |tamperopt|
        case tamperopt
        when 'floor2xor'
          @string_tampererd = @string_tampererd.floor2xor
        when 'floor2greatest'
          @string_tampererd = @string_tampererd.floor2greatest
        when 'floor2div'
          @string_tampererd = @string_tampererd.floor2div
        when 'floor2round'
          @string_tampererd = @string_tampererd.floor2round
        when 'floor2rand'
          @string_tampererd = @string_tampererd.floor2rand
        end
      end
      return @string_tampererd
    else
      return string
    end
  end

  # Do the tampering when called from injector classes or wheerever...
  def space(string)
    if @tampersql
      @string_tampererd = string
      @tamper.each do |tamperopt|
        case tamperopt
        when 'space2comment'
          @string_tampererd = @string_tampererd.space2comment
        when 'space2mycomment'
          @string_tampererd = @string_tampererd.space2mycomment
        when 'space2dash'
          @string_tampererd = @string_tampererd.space2dash
        when 'space2dashline'
          @string_tampererd = @string_tampererd.space2dashline
        when 'space2hash'
          @string_tampererd = @string_tampererd.space2hash
        when 'space2hashline'
          @string_tampererd = @string_tampererd.space2hashline
        when 'space2mssql'
          @string_tampererd = @string_tampererd.space2mssql
        when 'space2mysql'
          @string_tampererd = @string_tampererd.space2mysql
        when 'space2rand'
          @string_tampererd = @string_tampererd.space2rand
        when 'space2oa'
          @string_tampererd = @string_tampererd.space2oa
        when 'space2o9'
          @string_tampererd = @string_tampererd.space2o9
        when 'space2ob'
          @string_tampererd = @string_tampererd.space2ob
        when 'space2oc'
          @string_tampererd = @string_tampererd.space2oc
        when 'space2od'
          @string_tampererd = @string_tampererd.space2od
        when 'space2plus'
          @string_tampererd = @string_tampererd.space2plus
        end
      end
      return @string_tampererd
    else
      return string
    end
  end

  # Do the tampering when called from injector classes or wheerever...
  def comma(string)
    if @tampersql
      @string_tampererd = string
      @tamper.each do |tamperopt|
        case tamperopt
        when 'comma2comm'
          @string_tampererd = @string_tampererd.comma2comm
        when 'comma2mycomm'
          @string_tampererd = @string_tampererd2mycomm
        when 'comma2char'
          @string_tampererd = @string_tampererd.comma2char
        end
      end
      return @string_tampererd
    else
      return string
    end
  end

  # Do the tampering when called from injector classes or wheerever...
  def add(string)
    if @tampersql
      @string_tampererd = string
      @tamper.each do |tamperopt|
        case tamperopt
        when 'addnull'
          @string_tampererd = @string_tampererd.addnull
        when 'adddash'
          @string_tampererd = @string_tampererd.adddash
        when 'addsdash'
          @string_tampererd = @string_tampererd.addsdash
        when 'addhash'
          @string_tampererd = @string_tampererd.addhash
        when 'addcomm'
          @string_tampererd = @string_tampererd.addcomm
        when 'addsp'
          @string_tampererd = @string_tampererd.addsp
        end
      end
      return @string_tampererd
    else
      return string
    end
  end

  # Flip the TamperSQL Check var back to false
  def close
    @tampersql=false
  end
end
