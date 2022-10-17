package com.samin.sanitizerProvider.provider;

import org.jboss.logging.Logger;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

import javax.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;


public class SanitizerProvider implements FormAction {

    private static final Logger log = Logger.getLogger(SanitizerProvider.class);

    @Override
    public void buildPage(FormContext formContext, LoginFormsProvider loginFormsProvider) {

    }

    @Override
    public void validate(ValidationContext context) {
        log.info("----------------------Sanitizer------------------------");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        String eventError = Errors.INVALID_REGISTRATION;

        formData.forEach((s, strings) -> {

            String currentField = strings.get(0);

            if (isSQLinjection(currentField)) {
                errors.add(new FormMessage(s, "Invalid "+s));
            }

        });

        if (errors.size() > 0) {
            context.error(eventError);
            context.validationError(formData, errors);
        } else {

            formData.forEach((s, strings) -> {

                String currentField = strings.get(0);

                String sanitizedField = stripXSS(currentField);

                if (!currentField.equals(sanitizedField)){

                    log.info("XSS attack defeated!!!");

                    strings.clear();
                    strings.add(sanitizedField);

                }

            });

            context.success();
        }
    }

    private String stripXSS(String value) {

        if (value != null) {

            // Avoid null characters
            value = value.replaceAll("", "");

            // Avoid anything between script tags
            Pattern scriptPattern = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid anything in a src='...' type of expression
            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Remove any lonesome </script> tag
            scriptPattern = Pattern.compile("</script>", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Remove any lonesome <script ...> tag
            scriptPattern = Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid eval(...) expressions
            scriptPattern = Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid expression(...) expressions
            scriptPattern = Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid javascript:... expressions
            scriptPattern = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid vbscript:... expressions
            scriptPattern = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");

            // Avoid onload= expressions
            scriptPattern = Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");

        }
        return value;

    }

    private boolean isSQLinjection(String currentField) {

        return is_always_trueOrFalse(currentField)
                || comment_at_the_end(currentField)
                || stacking_queries(currentField)
                || union_set(currentField)
                || sleep_func(currentField);
    }

    private boolean sleep_func(String currentField) {

        if (currentField.toLowerCase().contains("pg_sleep(")) {
            log.info("Sleep function found!!!");
            return true;
        }
        return false;
    }

    private boolean union_set(String currentField) {
        if (currentField.toLowerCase().contains("union") && currentField.toLowerCase().contains("select")) {
            log.info("union sets found!!!");
            return true;
        }
        return false;
    }

    private boolean stacking_queries(String currentField) {

        if (currentField.contains(";")) {
            log.info("Stacking queries found!!!");
            return true;
        }
        return false;
    }

    private boolean comment_at_the_end(String currentField) {

        if (currentField.contains("--")) {
            log.info("Comment at the end of statement found!!!");
            return true;
        }
        return false;
    }

    private boolean is_always_trueOrFalse(String currentField) {

        if (currentField.contains("=")) {
            log.info("Always true/false condition found!!!");
            return true;
        }
        return false;

    }

    @Override
    public void success(FormContext formContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}
