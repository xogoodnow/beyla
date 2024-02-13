---
title: Set up Beyla
menuTitle: Setup
description: Learn how to set up and run Beyla.
weight: 1
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/
---

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo-2.png)

# Set up Beyla

There are different options to set up and run Beyla:

1. [As a standalone Linux process]({{< relref "./standalone.md" >}}).
2. [With Docker to instrument a process running in a container]({{< relref "./docker.md" >}}).
3. [As a Kubernetes DaemonSet or as a sidecar container]({{< relref "./kubernetes.md" >}})

For information on configuration options and data export modes, see the [Configure Beyla]({{< relref "../configure/_index.md" >}}) documentation.

{{< admonition type="note" >}}
If you are using Beyla to generate traces, make sure you've read the documentation section on configuring
the [Routes Decorator]({{< relref "../configure/options#routes-decorator" >}}). Since Beyla auto-instruments your application without any
special language level support, configuring the low cardinality routes decorator is very important for optimal results.
{{< /admonition >}}