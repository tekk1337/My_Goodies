#!/bin/bash
if [ -d /opt/ds_agent ]; then
            echo "Trend Version: $(/opt/ds_agent/dsa_query -c "GetPluginVersion" | grep '.core:' | cut -d' ' -f 2)"
      else
            echo "Trend is not installed"

fi

if [ -f /etc/panopta-agent/panopta_agent.cfg ]; then
            echo "Panopta Version: $(grep -i version /etc/panopta-agent/panopta_agent.cfg | cut -d' ' -f 3)"
      else
            echo "Panopta is not installed"
fi

if [ -f /usr/local/qualys/cloud-agent/bin/qualys-cloud-agent ]; then
            echo "Qualys Version: "$(ls -d /usr/share/doc/qualys-cloud-agent-* | rev| cut -d'/' -f1 | rev | cut -d'-' -f4-)
      else
            echo "Qualys is not installed"
fi

if [ -f /opt/armor/filebeat-*/filebeat ]; then
            echo "Filebeat Version: $(/opt/armor/filebeat-*/filebeat version | cut -d' ' -f 3)"
      else
            echo "Filebeat is not installed"
fi