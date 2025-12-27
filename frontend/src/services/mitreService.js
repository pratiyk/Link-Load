import apiClient, { API_BASE_URL } from "../config/api";

const MITRE_TECHNIQUES_ENDPOINT = `${API_BASE_URL}/api/v1/mitre/techniques`;

const mitreService = {
    async getAllTechniques() {
        const response = await apiClient.get(MITRE_TECHNIQUES_ENDPOINT);
        return response.data;
    }
};

export default mitreService;
