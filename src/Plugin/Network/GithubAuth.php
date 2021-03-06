<?php

namespace Drupal\social_auth_github\Plugin\Network;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\social_auth_github\GithubAuthPersistentDataHandler;
use Drupal\social_api\Plugin\NetworkBase;
use Drupal\social_api\SocialApiException;
use Drupal\social_auth_github\Settings\GithubAuthSettings;
use Symfony\Component\DependencyInjection\ContainerInterface;
use League\OAuth2\Client\Provider\Github;

/**
 * Defines a Network Plugin for Social Auth Github.
 *
 * @package Drupal\simple_fb_connect\Plugin\Network
 *
 * @Network(
 *   id = "social_auth_github",
 *   social_network = "Github",
 *   type = "social_auth",
 *   handlers = {
 *     "settings": {
 *       "class": "\Drupal\social_auth_github\Settings\GithubAuthSettings",
 *       "config_id": "social_auth_github.settings"
 *     }
 *   }
 * )
 */
class GithubAuth extends NetworkBase implements GithubAuthInterface {

  /**
   * The Github Persistent Data Handler.
   *
   * @var \Drupal\social_auth_github\GithubAuthPersistentDataHandler
   */
  protected $persistentDataHandler;

  /**
   * The logger factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactory
   */
  protected $loggerFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $container->get('social_auth_github.persistent_data_handler'),
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('entity_type.manager'),
      $container->get('config.factory'),
      $container->get('logger.factory')
    );
  }

  /**
   * GithubAuth constructor.
   *
   * @param \Drupal\social_auth_github\GithubAuthPersistentDataHandler $persistent_data_handler
   *   The persistent data handler.
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param array $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration factory object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(GithubAuthPersistentDataHandler $persistent_data_handler,
                              array $configuration,
                              $plugin_id,
                              array $plugin_definition,
                              EntityTypeManagerInterface $entity_type_manager,
                              ConfigFactoryInterface $config_factory,
                              LoggerChannelFactoryInterface $logger_factory) {

    parent::__construct($configuration, $plugin_id, $plugin_definition, $entity_type_manager, $config_factory);

    $this->persistentDataHandler = $persistent_data_handler;
    $this->loggerFactory = $logger_factory;
  }

  /**
   * Sets the underlying SDK library.
   *
   * @return \Github\Github
   *   The initialized 3rd party library instance.
   *
   * @throws SocialApiException
   *   If the SDK library does not exist.
   */
  protected function initSdk() {

    $class_name = '\League\OAuth2\Client\Provider\Github';
    if (!class_exists($class_name)) {
      throw new SocialApiException(sprintf('The Github Library for the league oAuth not found. Class: %s.', $class_name));
    }
    /* @var \Drupal\social_auth_github\Settings\GithubAuthSettings $settings */
    $settings = $this->settings;

    if ($this->validateConfig($settings)) {
      // All these settings are mandatory.
      $league_settings = [
        'clientId'          => $settings->getClientId(),
        'clientSecret'      => $settings->getClientSecret(),
        'redirectUri'       => $GLOBALS['base_url'] . '/user/login/github/callback'
      ];

      return new Github($league_settings);
    }
    return FALSE;
  }

  /**
   * Checks that module is configured.
   *
   * @param \Drupal\social_auth_github\Settings\GithubAuthSettings $settings
   *   The Github auth settings.
   *
   * @return bool
   *   True if module is configured.
   *   False otherwise.
   */
  protected function validateConfig(GithubAuthSettings $settings) {
    $client_id = $settings->getClientId();
    $client_secret = $settings->getClientSecret();
    if (!$client_id || !$client_secret ) {
      $this->loggerFactory
        ->get('social_auth_github')
        ->error('Define App ID and App Secret on module settings.');
      return FALSE;
    }

    return TRUE;
  }

}
