#include "wireguard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * Generate a private key and store it in result.
 * @param result    Pointer to the location where the key will be stored.
 */
void generate_private_key(unsigned char *result)
{
    wg_generate_private_key(result);
}

/**
 * Generate a public key and store it in result.
 * @param private   The private key to which the public key should correspond.
 * @param result    Pointer to the location where the key will be stored.
 */
void generate_public_key(unsigned char *private, unsigned char *result)
{
    wg_generate_public_key(result, private);
}

void key_to_string(wg_key key, char *result)
{
    wg_key_to_base64(result, key);
}

void key_from_string(char *string, wg_key key)
{
    wg_key_from_base64(key, string);
}

void add_server_device(char *device_name, uint16_t port, wg_key private_key)
{
    wg_device new_device = {
        .flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
        .listen_port = port,
    };

    snprintf(new_device.name, IFNAMSIZ, "%s", device_name);
    memcpy(new_device.private_key, private_key, sizeof(new_device.private_key));

    if (wg_add_device(new_device.name) < 0) {
        perror("Unable to add device");
        exit(1);
    }

    if (wg_set_device(&new_device) < 0) {
        perror("Unable to set device");
        exit(1);
    }
}

void add_client_device(char *device_name, wg_key private_key)
{
    wg_device new_device = {
        .flags = WGDEVICE_HAS_PRIVATE_KEY,
    };

    snprintf(new_device.name, IFNAMSIZ, "%s", device_name);
    memcpy(new_device.private_key, private_key, sizeof(new_device.private_key));

    if (wg_add_device(new_device.name) < 0) {
        perror("Unable to add device");
        exit(1);
    }

    if (wg_set_device(&new_device) < 0) {
        perror("Unable to set device");
        exit(1);
    }
}

/**
 * Add a peer to device 'device_name'.
 * @param device_name
 * @param public_key
 * @param ip_address
 */
void add_server_peer(char *device_name, unsigned char *public_key, char *ip_address, uint16_t port)
{
    struct sockaddr_in dest_addr;
    bzero(&dest_addr, sizeof (dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &dest_addr.sin_addr);

    wg_allowedip allowed_ip;
    bzero(&allowed_ip, sizeof (allowed_ip));
    inet_pton(AF_INET, "0.0.0.0", &allowed_ip.ip4);
    allowed_ip.family = AF_INET;
    allowed_ip.cidr = 0;

    wg_peer new_peer = {
        .flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS
    };

    new_peer.endpoint.addr4 = dest_addr;
    new_peer.first_allowedip = &allowed_ip;
    new_peer.last_allowedip = &allowed_ip;
    memcpy(new_peer.public_key, public_key, sizeof(new_peer.public_key));
    wg_device *device;
    if(wg_get_device(&device, device_name) < 0) {
        perror("Unable to get device");
        exit(1);
    }
    wg_peer *peer;
    if (device->last_peer == NULL) {
        device->first_peer = &new_peer;
        device->last_peer = &new_peer;
    } else {
        peer = device->last_peer;
        peer->next_peer = &new_peer;
        device->last_peer = &new_peer;
    }

    wg_set_device(device);
}

/**
 * Add a peer to device 'device_name'.
 * @param device_name
 * @param public_key
 * @param ip_address
 */
void add_client_peer(char *device_name, unsigned char *public_key, char *ip_address)
{
    wg_allowedip allowed_ip;
    bzero(&allowed_ip, sizeof (allowed_ip));
    inet_pton(AF_INET, ip_address, &allowed_ip.ip4);
    allowed_ip.family = AF_INET;
    allowed_ip.cidr = 32;

    wg_peer new_peer = {
        .flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS
    };

    new_peer.first_allowedip = &allowed_ip;
    new_peer.last_allowedip = &allowed_ip;
    memcpy(new_peer.public_key, public_key, sizeof(new_peer.public_key));
    wg_device *device;
    if(wg_get_device(&device, device_name) < 0) {
        perror("Unable to get device");
        exit(1);
    }
    wg_peer *peer;
    if (device->last_peer == NULL) {
        device->first_peer = &new_peer;
        device->last_peer = &new_peer;
    } else {
        peer = device->last_peer;
        peer->next_peer = &new_peer;
        device->last_peer = &new_peer;
    }

    wg_set_device(device);
}

int delete_device(char *device_name)
{
    if (wg_del_device(device_name) < 0) {
        perror("Unable to delete device");
        return 1;
    }
    return 0;
}

void list_devices(void)
{
    char *device_names, *device_name;
    size_t len;

    device_names = wg_list_device_names();
    if (!device_names) {
        perror("Unable to get device names");
        exit(1);
    }
    
    wg_for_each_device_name(device_names, device_name, len) {
        wg_device *device;
        wg_peer *peer;
        wg_key_b64_string key;

        if (wg_get_device(&device, device_name) < 0) {
            perror("Unable to get device");
            continue;
        }
        if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) {
            wg_key_to_base64(key, device->public_key);
            printf("%s has public key %s\n", device_name, key);
        } else
            printf("%s has no public key\n", device_name);
        wg_for_each_peer(device, peer) {
            wg_key_to_base64(key, peer->public_key);
            printf(" - peer %s\n", key);
        }
        wg_free_device(device);
    }
    free(device_names);
}

// BUG/TODO: check max_size!!!
void get_devices(char *device_list, uint max_size)
{
    char *device_names, *device_name;
    size_t len;
    char buf[31];
    const int tmpsize = 21;
    uint cx;

    device_list[0]='\0';

    device_names = wg_list_device_names();
    if (!device_names) {
      strcpy(device_list,"{}");
      return;
    }

    strcpy(device_list,"{");
    wg_for_each_device_name(device_names, device_name, len) {
      wg_device *device;
      wg_peer *peer;
      wg_key_b64_string key;

      if (wg_get_device(&device, device_name) < 0) {
        //perror("Unable to get device");
        continue;
      }

      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"%s\":{",device_name);
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      //sprintf(device_list,"%s\"name\" : \"%s\",",device->name);
      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"ifindex\" : %d,",device->ifindex);
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"flags\": %d,",device->flags);
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      wg_key_to_base64(key,device->public_key);
      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"public_key\" : \"%s\",",key);
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      wg_key_to_base64(key,device->private_key);
      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"private_key\" : \"%s\",",key);
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"fwmark\" : %d,",device->fwmark);
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"listen_port\" : %d,\"peers\":[{",device->listen_port);
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      //printf("DEBUG: %s",device_list);
      if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) {
        wg_key_to_base64(key, device->public_key);
      }
      wg_for_each_peer(device, peer) {
        wg_key_to_base64(key, peer->public_key);
        if (peer->flags & WGPEER_HAS_PUBLIC_KEY) {
          wg_key_to_base64(key,peer->public_key);
          cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"public_key\" : \"%44s\",",key);
          if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
        }
        if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
          wg_key_to_base64(key,peer->preshared_key);
          cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"preshared_key\"  : \"%44s\",",key);
          if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
        }
        if (peer->endpoint.addr.sa_family == AF_INET) {
          cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"endpoint\" : \"%s\",",inet_ntoa(peer->endpoint.addr4.sin_addr));
          if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
        }
        if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL){
          cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"keepalive\" : %d,",peer->persistent_keepalive_interval);
          if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
        }
        cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"rx_bytes\" : %lu,",peer->rx_bytes);
        if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
        cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"tx_bytes\" : %lu,",peer->tx_bytes);
        if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
        strftime(buf, tmpsize, "%Y-%m-%d %H:%M:%S", gmtime(&peer->last_handshake_time.tv_sec));
        cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"\"last_handshake_time\": \"%29s.%09ld\"},{",buf,peer->last_handshake_time.tv_nsec);
        if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      }
      device_list[strlen(device_list)-2] = '\0';
      cx=snprintf(device_list+strlen(device_list),max_size-strlen(device_list),"]},");
      if (cx<0 || max_size-strlen(device_list)<=2){strcpy(device_list,"{\"error\":\"overflow\"}");return;}
      wg_free_device(device);
    }
    free(device_names);
    device_list[strlen(device_list)-2] = '\0';
    strcat(device_list,"}}");
}
