require 'spec_helper'

describe OmniAuth::Strategies::GoTo do
  let(:access_token) { instance_double('AccessToken', :options => {}, :[] => 'user') }
  let(:parsed_response) { instance_double('ParsedResponse') }
  let(:response) { instance_double('Response', :parsed => parsed_response) }

  let(:enterprise_site)          { 'https://some.other.site.com' }
  let(:enterprise_authorize_url) { 'https://some.other.site.com/login/oauth/authorize' }
  let(:enterprise_token_url)     { 'https://some.other.site.com/login/oauth/token' }
  let(:enterprise) do
    OmniAuth::Strategies::GoTo.new('GOTO_CLIENT_ID', 'GOTO_CLIENT_SECRET',
        {
            :client_options => {
                :site => enterprise_site,
                :authorize_url => enterprise_authorize_url,
                :token_url => enterprise_token_url
            }
        }
    )
  end

  subject do
    OmniAuth::Strategies::GoTo.new({})
  end

  before(:each) do
    allow(subject).to receive(:access_token).and_return(access_token)
  end

  context 'client options' do
    it 'should have correct authorize url' do
      expect(subject.options.client_options.authorize_url).to eq('https://api.getgo.com/oauth/v2/authorize')
    end

    it 'should have correct token url' do
      expect(subject.options.client_options.token_url).to eq('https://api.getgo.com/oauth/v2/token')
    end

    describe 'should be overrideable' do
      it 'for site' do
        expect(enterprise.options.client_options.site).to eq(enterprise_site)
      end

      it 'for authorize url' do
        expect(enterprise.options.client_options.authorize_url).to eq(enterprise_authorize_url)
      end

      it 'for token url' do
        expect(enterprise.options.client_options.token_url).to eq(enterprise_token_url)
      end
    end
  end
end
