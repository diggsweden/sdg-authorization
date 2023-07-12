package se.digg.sdg.sample.client.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * Application error controller.
 */
@Controller
@ControllerAdvice
@Slf4j
public class ErrorController extends AbstractErrorController {

  @Setter
  @Value("${server.servlet.context-path}")
  private String contextPath;

  /**
   * Constructor.
   */
  public ErrorController() {
    super(new DefaultErrorAttributes());
  }

  /**
   * Error handler.
   *
   * @param request the HTTP request
   * @return a model and view object
   */
  @RequestMapping("/error")
  public ModelAndView handleError(final HttpServletRequest request) {

    final Map<String, Object> errorAttributes = this.getErrorAttributes(request, ErrorAttributeOptions.defaults());

    if (log.isInfoEnabled()) {
      final StringBuffer sb = new StringBuffer();
      for (final Map.Entry<String, Object> e : errorAttributes.entrySet()) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        sb.append(e.getKey()).append("=").append(e.getValue());
      }
      log.info("Error: {}", sb.toString());
    }

    final ModelAndView mav = new ModelAndView("error");

    final Exception exception = this.getException(request, Exception.class);
    if (exception != null) {
      log.info("Reporting error: exception='{}',message='{}'", exception.getClass().getName(), exception.getMessage());
      mav.addObject("exceptionClass", exception.getClass().getName());
      mav.addObject("message", exception.getMessage());
    }
    else {
      final HttpStatus status = this.getStatus(request);

      if (HttpStatus.NOT_FOUND.equals(status)) {
        mav.addObject("message", "Not Found");
      }
      else {
        mav.addObject("message", "Internal error");
      }
    }
    return mav;
  }

  /**
   * Returns the exception from the error attributes.
   *
   * @param request the HTTP request
   * @param exceptionClass the exception class we are looking for
   * @return the exception or null
   */
  protected <T extends Exception> T getException(final HttpServletRequest request, final Class<T> exceptionClass) {
    Exception e = (Exception) request.getAttribute("javax.servlet.error.exception");
    while (e != null) {
      if (exceptionClass.isInstance(e)) {
        return exceptionClass.cast(e);
      }
      e = (Exception) e.getCause();
    }
    return null;
  }

}
