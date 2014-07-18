class Devise::PasswordExpiredController < ActiveAdmin::Devise::SessionsController
  skip_before_filter :handle_password_change
  prepend_before_filter :authenticate_scope!, :only => [:show, :update]

  def show
    if not resource.nil? and resource.need_change_password?
      # respond_with(resource)
    else
      redirect_to :root
    end
  end


  def update
    warden.session(resource_name)[:password_confirmation] ||= SecureRandom.base64 #makes changing password mandatory
    if resource.update_with_password(params[:admin_user])
      warden.session(resource_name)[:password_expired] = false
      set_flash_message :notice, :updated
      sign_in resource_name, resource, :bypass => true

      redirection_path = 
        if ActiveRecord::Base.connection.table_exists? 'current_namespaces' and CurrentNamespace.count > 0 and !Rails.env.development?
          CurrentNamespace.first.current_namespace.to_sym || "/admin"
        else
          "/admin"
        end
      redirect_to stored_location_for(resource_name) || redirection_path
    else
      clean_up_passwords(resource)
      render :show
    end
  end

  private
  def scope
    resource_name.to_sym
  end

  def authenticate_scope!
    send(:"authenticate_#{resource_name}!")
    self.resource = send("current_#{resource_name}")
  end
end
