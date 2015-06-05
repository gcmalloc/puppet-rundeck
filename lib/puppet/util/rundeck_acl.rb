module Puppet::Util::RundeckACL
  
  class RundeckValidator

    def raise_err(msg)
      raise(Puppet::ParseError, "The policy is invalid - #{msg}")
    end

    def validate_description(description)
      if !description.is_a? String
        raise_err('description is not a String')
      end
    end

    def validate_context(context)
      if !context.is_a? Hash
        raise_err('context is not a Hash')
      elsif context.empty?
        raise_err('context is empty')
      else
        if !context['project'].is_a? String
          raise_err('context:project is not a String')
        end
      end
    end

    def validate_rule_action(type, type_section, scope)
      action_found = false
      actions = []
      kind = ''

      if type_section.empty?
        raise_err("for:#{type} is empty")
      end
      type_section.each do |e|
        if e.is_a? Hash
          e.each do |k,v|
            if k.eql?('allow') or k.eql?('deny')
              action_found = true
              actions = v
            elsif ['match','equals','contains'].include?(k)
              kind = v['kind']
            end
          end
        else
          raise_err("for:#{type} entry is not a Hash")
        end

        if !action_found
          raise_err("for:#{type} does not contain a rule action of [allow,deny]")
        else
          validate_proj_actions(type, actions, kind)
        end
      end
      
    end

    def validate_proj_actions(type, actions, kind)
      proj_actions = {
        'resource' => {
          'job'   => ['create','delete'],
          'node'  => ['read','create','update','refresh'],
          'event' => ['read','create']
         },
        'adoc' => ['read','run','runAs','kill','killAs'],
        'job' => {
          'name' => ['read','update','delete','run','runAs','kill','killAs','create'],
          'group' => ['read','update','delete','run','runAs','kill','killAs','create']
        }
      }

      case type
      when 'resource'
        case kind
        when 'job', 'node', 'event'
          actions.each do |action|
            if !proj_actions[type][kind].include?(action)
              raise_err("for:resource kind:#{kind} can only contain actions #{proj_actions[type][kind]}")
            end
          end
        else
          #
        end
      when 'adhoc'
       #
      when 'job'
       # 
      else
        #
      end
    end

    def validate_matching(type, type_section)
      matching_found = false
      if type_section.empty?
        raise Puppet::Error, ("The policy is invalid - for:#{type} is empty")
      end
      type_section.each do |e|
        if e.is_a? Hash
          e.each do |k,v|
            if k.eql?('match') or k.eql?('equals') or k.eql?('contains')
              matching_found = true
            end
          end
        else
          raise Puppet::ParseError, ("The policy is invalid - for:#{type} entry is not a Hash")
        end
      end
      if !matching_found
        raise Puppet::ParseError, ("The policy is invalid - for:#{type} does not contain a matching statement of [match,equals,contains]")
      end
    end

    def validate_for(for_section, scope)
      if !for_section.is_a? Hash
        raise Puppet::ParseError, ("The policy is invalid - for is not a Hash")
      elsif for_section.empty?
        raise Puppet::ParseError, ("The policy is invalid - for is empty")          
      else
        resource_types = ['job','node','adhoc','project','resource']
        #rule_action = ['allow','deny']
        #matching = ['match','equals','contains']

        for_section.each do |k,v|
          if !resource_types.include?(k)
            raise Puppet::ParseError, ("The policy is invalid - for section must only contain [job,node,adhoc,project,resource]")
          end
        end
           
        resource_types.each do |type|
          if for_section.has_key?(type)
            if !for_section[type].is_a? Array
              raise Puppet::ParseError, ("The policy is invalid - for:#{type} is not an Array")
            elsif for_section[type].empty?
              raise Puppet::ParseError, ("The policy is invalid - for:#{type} is empty")
            else
              validate_rule_action(type, for_section[type], scope)
              validate_matching(type, for_section[type])
            end
          end
        end
      end
    end
  end

  def validate_acl(hash)
    rv = RundeckValidator.new
    rv.validate_description(hash['description'])
    rv.validate_context(hash['context'])
    rv.validate_for(hash['for'], '')
  end

  module_function :validate_acl
end