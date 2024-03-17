import { ContractStorage } from "../../helpers/ContractStorage";
import { Deployment } from "../../helpers/Deployment";
import { EContracts, IDeployParams } from "../../helpers/types";

const deployment = Deployment.getInstance();
const storage = ContractStorage.getInstance();

/**
 * Deploy step registration and task itself
 */
deployment
  .deployTask("full:deploy-gatekeepers", "Deploy gatekeepers")
  .setAction(async ({ incremental }: IDeployParams, hre) => {
    deployment.setHre(hre);
    const deployer = await deployment.getDeployer();

    const freeForAllGatekeeperContractAddress = storage.getAddress(EContracts.FreeForAllGatekeeper, hre.network.name);
    const easGatekeeperContractAddress = storage.getAddress(EContracts.EASGatekeeper, hre.network.name);
    const deployFreeForAllGatekeeper = deployment.getDeployConfigField(EContracts.FreeForAllGatekeeper, "deploy");
    const deployEASGatekeeper = deployment.getDeployConfigField(EContracts.EASGatekeeper, "deploy");
    const skipDeployFreeForAllGatekeeper = deployFreeForAllGatekeeper === false;
    const skipDeployEASGatekeeper = deployEASGatekeeper === false;

    const canSkipDeploy =
      incremental &&
      (freeForAllGatekeeperContractAddress || skipDeployFreeForAllGatekeeper) &&
      (easGatekeeperContractAddress || skipDeployEASGatekeeper) &&
      (!skipDeployFreeForAllGatekeeper || !skipDeployEASGatekeeper);

    if (canSkipDeploy) {
      return;
    }

    if (!skipDeployFreeForAllGatekeeper) {
      const freeFroAllGatekeeperContract = await deployment.deployContract(EContracts.FreeForAllGatekeeper, deployer);

      await storage.register({
        id: EContracts.FreeForAllGatekeeper,
        contract: freeFroAllGatekeeperContract,
        args: [],
        network: hre.network.name,
      });
    }
  });
