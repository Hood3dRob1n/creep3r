# This is a drop in IRB Console
# helpful for debugging and messing around

# To make use of it, just call a new session, like so:
# IRB.start_session(binding)

# This magical Ruby code snippet is actually borrowed from here:
# http://jasonroelofs.com/2009/04/02/embedding-irb-into-your-ruby-application/

require 'irb'

module IRB # :nodoc:
  def self.start_session(binding)
    unless @__initialized
      args = ARGV
      ARGV.replace(ARGV.dup)
      IRB.setup(nil)
      ARGV.replace(args)
      @__initialized = true
    end

    workspace = WorkSpace.new(binding)

    # Set things up so we have simple prompt
    IRB.conf[:PROMPT_MODE]=:SIMPLE

    irb = Irb.new(workspace)
    @CONF[:IRB_RC].call(irb.context) if @CONF[:IRB_RC]
    @CONF[:MAIN_CONTEXT] = irb.context

    catch(:IRB_EXIT) do
      irb.eval_input
    end

    # Fix to catch & allow gracefull exiting....idk why though...
    catch(:IRB_EXIT) do
      main_menu
    end
  end
end
