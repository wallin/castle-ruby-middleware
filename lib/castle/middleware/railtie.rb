# frozen_string_literal: true

require 'rails/railtie'

module Castle
  class Middleware
    class Railtie < ::Rails::Railtie
      initializer 'castle.middleware.rails' do |app|
        app.config.middleware.insert_after Rack::Sendfile,
                                           Castle::Middleware::Sensor
        app.config.middleware.insert_after Rack::Sendfile,
                                           Castle::Middleware::Authenticating
        # app.config.middleware.insert_after ActionDispatch::Flash,
        #                                    Castle::Middleware::Tracking
      end
    end
  end
end
