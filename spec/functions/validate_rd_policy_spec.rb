require 'spec_helper'

describe 'validate_rd_policy' do
  describe 'signature validation' do
    it { is_expected.not_to eq(nil) }
    it { is_expected.to run.with_params().and_raise_error(Puppet::ParseError, /wrong number of arguments/i) }
 
    describe 'basic invalid inputs' do
     it { is_expected.to run.with_params(1).and_raise_error(Puppet::ParseError, /is not a Hash or Array of hashes/) }
     it { is_expected.to run.with_params(true).and_raise_error(Puppet::ParseError, /is not a Hash or Array of hashes/) }
     it { is_expected.to run.with_params('one').and_raise_error(Puppet::ParseError, /is not a Hash or Array of hashes/) }
    end

  end

  describe 'project policy' do
    describe 'valid policy' do
      test_policy = {
        'description' => 'Admin, all access',
        'context' => {
          'project' => '.*'
        },
        'for' => {
          'resource' => [
            { 'equals' => { 'kind' => 'job' }, 'allow' => ['create'] }
          ],
        },
        'by' => {
          'groups'    => ['admin'],
        }
      }

      it { is_expected.to run.with_params(test_policy) }
    end

    describe 'invalid policy' do
      it { is_expected.to run.with_params({}).and_raise_error(Puppet::ParseError, //)}
      
      it { is_expected.to run.with_params({
        'context' => {
          'project' => '.*'
        }
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - description is not a String')}
      
      it { is_expected.to run.with_params({
        'description' => {}
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - description is not a String')}

      
      it { is_expected.to run.with_params({
        'description' => 'test'
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - context is not a Hash')}

      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => {}
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - context is empty')}

      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => ''
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - context is not a Hash')}


      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => {
          'fubar' => ''
        }
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - context:project is not a String')}

     
      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => {
          'project' => {}
        }
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - context:project is not a String')}

      
      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => {
          'project' => '.*'
        },
        'for' => ''
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - for is not a Hash')}
      
      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => {
          'project' => '.*'
        },
        'for' => {}
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - for is empty')}
   
      
      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => {
          'project' => '.*'
        },
        'for' => {
          'fubar' => {}
        }
      }).and_raise_error(Puppet::ParseError, 'The policy is invalid - for section must only contain [job,node,adhoc,project,resource]')}
     
      ['job','node','adhoc','project','resource'].each do |type| 
      
        it { is_expected.to run.with_params({
          'description' => 'test',
          'context'     => {
            'project' => '.*'
          },
          'for' => {
            type => ''
          }
        }).and_raise_error(Puppet::ParseError, "The policy is invalid - for:#{type} is not an Array")}

        it { is_expected.to run.with_params({
          'description' => 'test',
          'context'     => {
            'project' => '.*'
          },
          'for' => {
            type => {}
          }
        }).and_raise_error(Puppet::ParseError, "The policy is invalid - for:#{type} is not an Array")}

        it { is_expected.to run.with_params({
          'description' => 'test',
          'context'     => {
            'project' => '.*'
          },
          'for' => {
            type => []
          }
        }).and_raise_error(Puppet::ParseError, "The policy is invalid - for:#{type} is empty")}
      
        it { is_expected.to run.with_params({
          'description' => 'test',
          'context'     => {
            'project' => '.*'
          },
          'for' => {
            type => [{}]
          }
        }).and_raise_error(Puppet::ParseError, "The policy is invalid - for:#{type} does not contain a rule action of [allow,deny]")}

        it { is_expected.to run.with_params({
          'description' => 'test',
          'context'     => {
            'project' => '.*'
          },
          'for' => {
            type => [
              { 'equals' => { 'kind' => 'job' }, 'allow' => ['create'] },
              ''
            ]
          }
        }).and_raise_error(Puppet::ParseError, "The policy is invalid - for:#{type} entry is not a Hash")} 
    
        it { is_expected.to run.with_params({
          'description' => 'test',
          'context'     => {
            'project' => '.*'
          },
          'for' => {
            type => [
              { 'equals' => { 'kind' => 'job' }, 'fubar' => ['create'] },
            ]
          }
        }).and_raise_error(Puppet::ParseError, "The policy is invalid - for:#{type} does not contain a rule action of [allow,deny]")}

        it { is_expected.to run.with_params({
          'description' => 'test',
          'context'     => {
            'project' => '.*'
          },
          'for' => {
            type => [
              { 'fubar' => { 'kind' => 'job' }, 'deny' => ['create'] },
            ]
          }
        }).and_raise_error(Puppet::ParseError, "The policy is invalid - for:#{type} does not contain a matching statement of [match,equals,contains]")}
      end

      it { is_expected.to run.with_params({
        'description' => 'test',
        'context'     => {
          'project' => '.*'
        },
        'for' => {
          'resource' => [
            { 'equals' => { 'kind' => 'job' }, 'allow' => ['x'] },
          ]
        }
      }).and_raise_error(Puppet::ParseError, /^The policy is invalid - for:resource kind:job can only contain actions/) }
    end
  end

end