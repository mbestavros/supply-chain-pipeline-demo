from securesystemslib import interface
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock

def main():
  # Load Alice's private key to later sign the layout
  key_alice = interface.import_rsa_privatekey_from_file("alice")
  # Fetch and load Bob's and Carl's public keys
  # to specify that they are authorized to perform certain step in the layout
  key_bob = interface.import_rsa_publickey_from_file("../functionary_bob/bob.pub")

  layout = Layout.read({
      "_type": "layout",
      "keys": {
          key_bob["keyid"]: key_bob,
      },
      "steps": [{
          "name": "compile",
          "expected_materials": [],
          "expected_products": [["CREATE", "/home/runner/work/supply-chain-pipeline-demo/supply-chain-pipeline-demo/hello-go/hello-go"], ["DISALLOW", "*"]],
          "pubkeys": [key_bob["keyid"]],
          "expected_command": [
              "go",
              "build",
          ],
          "threshold": 1,
        },{
          "name": "move_allowlist_to_verifier",
          "expected_materials": [],
          "expected_products": [["CREATE", "/home/vagrant/allowlist.txt"], ["DISALLOW", "*"]],
          "pubkeys": [key_bob["keyid"]],
          "expected_command": [
              "scp",
              "/root/allowlist.txt",
              "vagrant@192.168.122.57:~"
          ],
          "threshold": 1,
        },{
          "name": "move_allowlist_to_root",
          "expected_materials": [],
          "expected_products": [["CREATE", "/root/allowlist.txt"], ["DISALLOW", "*"]],
          "pubkeys": [key_carl["keyid"]],
          "expected_command": [
            "cp",
            "/home/vagrant/allowlist.txt",
            "/root/"
          ],
          "threshold": 1,
        },{
          "name": "create_binary",
          "expected_materials": [],
          "expected_products": [["CREATE", "/root/demo/test-binary.sh"], ["DISALLOW", "*"]],
          "pubkeys": [key_carl["keyid"]],
          "expected_command": [
            "chmod",
            "+x",
            "/root/demo/test-binary.sh"
          ],
          "threshold": 1,
        },{
          "name": "move_binary_to_agent",
          "expected_materials": [],
          "expected_products": [["CREATE", "/home/vagrant/test-binary.sh"], ["DISALLOW", "*"]],
          "pubkeys": [key_carl["keyid"]],
          "expected_command": [
              "scp",
              "/root/demo/test-binary.sh",
              "vagrant@192.168.122.98:~"
          ],
          "threshold": 1,
        },{
          "name": "update_allowlist",
          "expected_materials": [
            ["MATCH", "/root/demo/functionary_carl/*", "WITH", "PRODUCTS", "FROM",
             "move_binary_to_agent"], ["DISALLOW", "*"],
          ],
          "expected_products": [
              ["CREATE", "/root/keylime-policy-importer/keylime-policy.json"], ["DISALLOW", "*"],
          ],
          "pubkeys": [key_carl["keyid"]],
          "expected_command": [
              "python3",
              "/root/keylime-policy-importer/importer.py",
              "-l",
              "/root/demo/functionary_carl/move_binary_to_agent.link",
              "-a",
              "/root/allowlist.txt",
          ],
          "threshold": 1,
        }],
      "inspect": [{
          "name": "untar",
          "expected_materials": [
              ["MATCH", "demo-project.tar.gz", "WITH", "PRODUCTS", "FROM", "package"],
              # FIXME: If the routine running inspections would gather the
              # materials/products to record from the rules we wouldn't have to
              # ALLOW other files that we aren't interested in.
              ["ALLOW", ".keep"],
              ["ALLOW", "alice.pub"],
              ["ALLOW", "root.layout"],
              ["DISALLOW", "*"]
          ],
          "expected_products": [
              ["MATCH", "demo-project/foo.py", "WITH", "PRODUCTS", "FROM", "update-version"],
              # FIXME: See expected_materials above
              ["ALLOW", "demo-project/.git/*"],
              ["ALLOW", "demo-project.tar.gz"],
              ["ALLOW", ".keep"],
              ["ALLOW", "alice.pub"],
              ["ALLOW", "root.layout"],
              ["DISALLOW", "*"]
          ],
          "run": [
              "tar",
              "xzf",
              "demo-project.tar.gz",
          ]
        }],
  })

  metadata = Metablock(signed=layout)

  # Sign and dump layout to "root.layout"
  metadata.sign(key_alice)
  metadata.dump("root.layout")
  print('Created demo in-toto layout as "root.layout".')

if __name__ == '__main__':
  main()
