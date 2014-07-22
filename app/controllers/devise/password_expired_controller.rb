class Devise::PasswordExpiredController < ActiveAdmin::Devise::SessionsController
  skip_before_filter    :handle_password_change
  prepend_before_filter :authenticate_scope!, :only => [:show, :update]
  before_filter         :handle_two_factor_authentication, :only => [:show, :update]

  def show
    if needs_two_factor
      two_factor_binding
    elsif not resource.nil? and resource.need_change_password?
      respond_with(resource)
    else
      redirect_to :root
    end
  end


  def update
    if needs_two_factor
      two_factor_binding
    elsif resource.update_with_password(params[:admin_user])
      warden.session(resource_name)[:password_expired] = false
      set_flash_message :notice, :updated
      sign_in resource_name, resource, :bypass => true

      redirection_path = 
        if ActiveRecord::Base.connection.table_exists? 'current_namespaces' and CurrentNamespace.count > 0
          CurrentNamespace.last.current_namespace.to_sym || "/admin"
        else
          "/admin"
        end
      redirect_to stored_location_for(resource_name) || redirection_path
    else
      clean_up_passwords(resource)
      respond_with(resource, action: :show)
    end
  end

  private
  def needs_two_factor
    signed_in?(scope) and warden.session(resource_name)[:need_two_factor_authentication]
  end

  def two_factor_binding
    handle_failed_second_factor(resource_name)
  end

  def scope
    resource_name.to_sym
  end

  def authenticate_scope!
    send(:"authenticate_#{resource_name}!")
    self.resource = send("current_#{resource_name}")
  end
end
