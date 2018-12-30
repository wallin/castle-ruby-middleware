# frozen_string_literal: true

module Castle
  class Middleware
    # Map a request path to a Castle event name
    class EventMapper
      Mapping = Struct.new(:event, :method, :path, :redirect_url,
                           :status, :properties, :user_traits_from_params, :authenticate,
                           :referer, :quitting, :deny, :challenge, :before)

      DEFAULT_CHALLENGE_URL = 'https://brissmyr.github.io/pages/challenge.html'
      DEFAULT_DENY_URL = 'https://brissmyr.github.io/pages/deny.html'

      class Response
        attr_accessor :url, :body, :headers, :status

        class << self
          def build(config, url)
            return unless config.is_a?(::Hash)

            new.tap do |obj|
              obj.url, obj.status, obj.headers, obj.body =
                config.values_at('url', 'status', 'headers', 'body')
              obj.url ||= url
            end
          end
        end
      end

      attr_accessor :mappings

      def initialize
        @mappings = []
      end

      def add(event, conditions)
        conditions = conditions.each_with_object({}) do |(k, v), hash|
          hash[k.to_sym] = v || ''
        end
        @mappings << Mapping.new(
          event.to_s,
          conditions[:method],
          conditions[:path],
          conditions[:redirect_url],
          conditions[:status],
          conditions.fetch(:properties, {}),
          conditions.fetch(:user_traits_from_params, {}),
          conditions.fetch(:authenticate, false),
          conditions[:referer],
          conditions.fetch(:quitting, false),
          Response.build(conditions[:deny], DEFAULT_DENY_URL),
          Response.build(conditions[:challenge], DEFAULT_CHALLENGE_URL),
          conditions.fetch(:before, false)
        )
      end

      def events
        @mappings.map(&:event)
      end

      def find(conditions)
        @mappings.select { |mapping| self.class.match?(mapping, conditions) }
      end

      def find_by_rack_request(status, path, headers, request, authenticate = false, before = false)
        find(
          status: status, # Rack status code
          method: request.request_method,
          path: path,
          authenticate: authenticate,
          referer: request.referer.to_s,
          redirect_url: headers ? headers['Location'] : nil,
          before: before
        )
      end

      def size
        @mappings.size
      end

      def self.build(config)
        config.each_with_object(new) do |(event, conditions), mapping|
          conditions = [conditions] unless conditions.is_a?(::Array)
          conditions.each { |c| mapping.add(event, c) }
        end
      end

      def self.match?(mapping, conditions)
        status, mtd, path, auth, referer, redirect_url, before = conditions.values_at(
          :status, :method, :path, :authenticate, :referer, :redirect_url, :before
        )

        return false if path.nil?

        (mapping.before == before) &&
          (mapping.authenticate == auth) &&
          match_prop?(mapping.status, status) &&
          match_prop?(mapping.method, mtd) &&
          match_prop?(mapping.redirect_url, redirect_url) &&
          match_prop?(mapping.path, path) &&
          match_prop?(mapping.referer, referer)
      end

      def self.match_prop?(prop_value, current)
        return true if current.nil? || prop_value.nil?

        prop_value = /^#{prop_value}$/ unless prop_value.is_a?(Regexp)

        !prop_value.match(current).nil?
      end
    end
  end
end
