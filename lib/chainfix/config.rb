require 'yaml'


CONFIG_FILE = File.join(ChainFix::BASE_DIR, 'data/config.yaml')

module ChainFix
  class Config
    def initialize
      File.open CONFIG_FILE, 'r' do |file|
        @data = YAML.load file
      end
    end

    def self.shared
      @shared = Config.new unless @shared
      @shared
    end
  end
end``
