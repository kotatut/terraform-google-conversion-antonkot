control_plane_endpoints_config { # i
    dns_endpoint_config { # i
        allow_external_traffic = false # i
    }
    ip_endpoints_config { # i
        enabled = true # i
    }
}

database_encryption { # i
    state    = "DECRYPTED" # i
}

enterprise_config { # i
    desired_tier = "STANDARD" # i
}

fleet { # i
    project = "cluster-converter-1" # i
}

master_auth { # i
    client_certificate_config { # i
        issue_client_certificate = false # i
    }
}

monitoring_config { # i
    enable_components = ["SYSTEM_COMPONENTS", "STORAGE", "POD", "DEPLOYMENT", "STATEFULSET", "DAEMONSET", "HPA", "CADVISOR", "KUBELET"] # i
    managed_prometheus { # i
        enabled = true # i
        auto_monitoring_config { # i
            scope = "NONE" # i
        }
    }
}

network_policy { # i
    enabled  = false # i
    provider = "PROVIDER_UNSPECIFIED" # i
}

node_pool_auto_config { # i
    resource_manager_tags = null # i
}
  
release_channel { # i
    channel = "UNSPECIFIED" # i
}

NODEPOOL:

name              = "pool-name"

initial_node_count = 1 # i

node_config { # i
    advanced_machine_features { # i
        enable_nested_virtualization = false # i
    }
    ...
    resource_manager_tags = {} # i
}

queued_provisioning { # i
    enabled = false # i
}