require "chainfix/version"

module Chainfix
  class Error < StandardError; end
  BASE_DIR = File.join(File.basename(__file__), '..')
  autoload :Config, 'chainfix/config'
  autoload :Command, 'chainfix/command'
end
